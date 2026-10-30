'use strict';

const {spawn} = require('node:child_process');
const {domainToASCII} = require('node:url');
const path = require('node:path');

const {validateEndpoint} = require('./yun_aliyun_mcp.cjs');

function normalizeDomain(value) {
  if (typeof value !== 'string' || value.trim() !== value || /[\/:@\s]/.test(value)) throw new Error('Invalid domain');
  const domain = domainToASCII(value).toLowerCase().replace(/\.$/, '');
  if (domain.length > 253 || !domain.includes('.') || domain.split('.').some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) throw new Error('Invalid domain');
  return domain;
}

function summarizeDns(data, domain) {
  if (!data || data.status !== 'completed' || data.domain !== domain || !Array.isArray(data.records)) throw new Error('Unexpected DNS response');
  const records = data.records.map(record => {
    const type = String(record.type ?? record.Type ?? '');
    const item = {
      host: record.host ?? record.rr ?? record.RR,
      type,
      status: record.status ?? record.Status,
      line: record.line ?? record.Line,
      ttl: record.ttl ?? record.TTL,
      id: record.id ?? record.record_id ?? record.RecordId,
    };
    const value = record.value ?? record.Value;
    if (['A', 'AAAA', 'CNAME', 'MX', 'NS'].includes(type.toUpperCase()) && typeof value === 'string' && value.length <= 253 && /^[a-zA-Z0-9_.:\-]+$/.test(value)) item.value = value;
    return item;
  });
  return {ok: true, domain, total: data.total, page: data.page, has_more: !!data.has_more, records};
}

function summarizeIcp(data, domain) {
  if (!data || data.Success !== true || !data.BeianOrderQueryResult || !Array.isArray(data.BeianOrderQueryResult.OrderList)) throw new Error('Unexpected filing response');
  return {
    ok: true,
    domain,
    page: data.BeianOrderQueryResult.PageNo,
    page_size: data.BeianOrderQueryResult.PageSize,
    orders: data.BeianOrderQueryResult.OrderList.map(order => ({status: order.OrderStatus, type: order.OrderType, created: order.GmtCreated})),
  };
}

function runQuery(action, domain, page) {
  const ENDPOINT = process.env.YUN_ALIYUN_DOMAIN_MCP_ENDPOINT;
  if (!ENDPOINT || !validateEndpoint(ENDPOINT).isDomain) throw new Error('Set a verified domain MCP endpoint locally');
  return new Promise((resolve, reject) => {
    const processChild = spawn(process.execPath, [path.join(__dirname, 'yun_aliyun_mcp.cjs'), ENDPOINT, '--silent'], {
      windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
    });
    let buffer = '';
    let completed = false;
    let timer;
    function finish(error, value) {
      if (completed) return;
      completed = true;
      clearTimeout(timer);
      processChild.stdin.end();
      processChild.kill();
      error ? reject(error) : resolve(value);
    }
    timer = setTimeout(() => finish(new Error('MCP connection timed out; finish browser authorization or check network')), 45000);
    processChild.stderr.resume();
    processChild.on('error', () => finish(new Error('Unable to start the Alibaba Cloud MCP client')));
    processChild.on('exit', () => finish(new Error('Alibaba Cloud MCP connection ended before a verified response')));
    processChild.stdout.on('data', chunk => {
      buffer += chunk.toString('utf8');
      if (buffer.length > 4 * 1024 * 1024) return finish(new Error('MCP response too large'));
      let end;
      while ((end = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, end);
        buffer = buffer.slice(end + 1);
        if (!line.trim()) continue;
        let message;
        try { message = JSON.parse(line); } catch { return finish(new Error('Invalid MCP response')); }
        if (message.id === 1) {
          if (!message.result || message.error) return finish(new Error('MCP initialization failed'));
          processChild.stdin.write(JSON.stringify({jsonrpc: '2.0', method: 'notifications/initialized'}) + '\n');
          const name = action === 'dns-list' ? 'dns_list' : 'icp_status';
          const args = action === 'dns-list' ? {domain, page} : {'domain-name': domain, 'page-no': page};
          processChild.stdin.write(JSON.stringify({jsonrpc: '2.0', id: 2, method: 'tools/call', params: {name, arguments: args}}) + '\n');
        } else if (message.id === 2) {
          if (message.error || message.result?.isError) return finish(new Error('Alibaba Cloud rejected the read-only request'));
          const content = message.result?.content?.find(item => item.type === 'text');
          if (!content) return finish(new Error('Alibaba Cloud returned no structured data'));
          try {
            const payload = JSON.parse(content.text);
            finish(null, action === 'dns-list' ? summarizeDns(payload, domain) : summarizeIcp(payload, domain));
          } catch { finish(new Error('Alibaba Cloud returned an unexpected or unsuccessful response')); }
        }
      }
    });
    processChild.stdin.write(JSON.stringify({jsonrpc: '2.0', id: 1, method: 'initialize', params: {protocolVersion: '2025-03-26', capabilities: {}, clientInfo: {name: 'yun-aliyun', version: '1.0.0'}}}) + '\n');
  });
}

async function main() {
  const [action, value, pageText, ...extra] = process.argv.slice(2);
  if (!['dns-list', 'icp-status'].includes(action) || !value || extra.length) throw new Error('Usage: yun_aliyun.cjs <dns-list|icp-status> <domain> [page]');
  const domain = normalizeDomain(value);
  const page = pageText === undefined ? 1 : Number(pageText);
  if (!Number.isInteger(page) || page < 1 || page > 1000) throw new Error('Invalid page');
  const result = await runQuery(action, domain, page);
  process.stdout.write(JSON.stringify(result) + '\n');
}

module.exports = {normalizeDomain, summarizeDns, summarizeIcp};
if (require.main === module) main().catch(error => {
  process.stderr.write(JSON.stringify({ok: false, error: error.message}) + '\n');
  process.exitCode = 1;
});
