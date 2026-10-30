'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {normalizeDomain, summarizeDns, summarizeIcp} = require('./yun_aliyun.cjs');

test('domain names are exact and cannot include URLs or paths', () => {
  assert.equal(normalizeDomain('Example.COM.'), 'example.com');
  for (const input of ['https://example.com', 'example.com/path', ' example.com', 'user@example.com', 'localhost', 'x..com']) {
    assert.throws(() => normalizeDomain(input));
  }
});

test('DNS summaries expose normal routing values but never TXT or unknown values', () => {
  const data = {status:'completed', domain:'example.com', total:3, page:1, has_more:false, records:[
    {host:'@',type:'A',value:'192.0.2.1'},
    {host:'_verify',type:'TXT',value:'private-verification-value'},
    {host:'x',type:'UNKNOWN',value:'private-unknown-value'},
  ]};
  const result = summarizeDns(data, 'example.com');
  assert.equal(result.records[0].value, '192.0.2.1');
  assert.equal('value' in result.records[1], false);
  assert.equal('value' in result.records[2], false);
  assert.doesNotMatch(JSON.stringify(result), /private-/);
  assert.throws(() => summarizeDns(data, 'other.example'));
});

test('filing summary keeps status and removes personal identifiers', () => {
  const source = {Success:true,BeianOrderQueryResult:{PageNo:1,PageSize:'10',OrderList:[{
    OrderStatus:'待提交订单',OrderType:'新增服务',GmtCreated:'2026-10-29',
    BaOrderId:'private-order',OrganizersName:'private-name',Phone:'private-phone',
  }]}};
  const result = summarizeIcp(source, 'example.com');
  assert.equal(result.orders[0].status, '待提交订单');
  assert.doesNotMatch(JSON.stringify(result), /private-/);
  assert.throws(() => summarizeIcp({Success:false}, 'example.com'));
});


test('background children are hidden even when their caller does not request it', () => {
  const cp = require('node:child_process');
  const {syncBuiltinESMExports} = require('node:module');
  const original = cp.spawn;
  let passed;
  try {
    cp.spawn = (command, args, options) => { passed = options; return {}; };
    require('./yun_aliyun_mcp.cjs').installHiddenSpawn();
    cp.spawn('example', [], {windowsHide: false, stdio: 'pipe'});
    assert.equal(passed.windowsHide, true);
    assert.equal(passed.stdio, 'pipe');
  } finally {
    cp.spawn = original;
    syncBuiltinESMExports();
  }
});


test('MCP endpoint accepts only verified Alibaba Cloud service shapes', () => {
  const {validateEndpoint} = require('./yun_aliyun_mcp.cjs');
  assert.equal(validateEndpoint('https://openapi-mcp.cn-hangzhou.aliyuncs.com/id/test/mcp').isDomain, false);
  assert.equal(validateEndpoint('https://openapi-mcp.cn-hangzhou.aliyuncs.com/s/Domain/domain/example-service/mcp').isDomain, true);
  for (const value of ['http://openapi-mcp.cn-hangzhou.aliyuncs.com/id/test/mcp', 'https://evil.example/id/test/mcp', 'https://openapi-mcp.cn-hangzhou.aliyuncs.com/id/test/mcp?token=x']) assert.throws(() => validateEndpoint(value));
});
