'use strict';

// Hide the proxy's PowerShell/browser-launch helper, while leaving the
// interactive authorization page visible to the user.
const childProcess = require('node:child_process');
const {syncBuiltinESMExports} = require('node:module');
const os = require('node:os');
const path = require('node:path');
const {pathToFileURL} = require('node:url');


function installHiddenSpawn() {
  const originalSpawn = childProcess.spawn;
  childProcess.spawn = function (command, args, options = {}) {
    return originalSpawn.call(this, command, args, {...options, windowsHide: true});
  };
  syncBuiltinESMExports();
}

function validateEndpoint(value) {
  let endpoint;
  try { endpoint = new URL(value); } catch { throw new Error('Invalid Alibaba Cloud MCP endpoint'); }
  const isDomain = /^\/s\/Domain\/domain\/[A-Za-z0-9_-]{4,128}\/mcp$/.test(endpoint.pathname);
  const isCore = /^\/id\/[A-Za-z0-9_-]+\/mcp$/.test(endpoint.pathname) ||
    /^\/accounts\/[A-Za-z0-9_-]+\/id\/[A-Za-z0-9_-]+\/mcp$/.test(endpoint.pathname);
  if (endpoint.protocol !== 'https:' || endpoint.hostname !== 'openapi-mcp.cn-hangzhou.aliyuncs.com' ||
      endpoint.port || endpoint.username || endpoint.password || endpoint.search || endpoint.hash || !(isDomain || isCore)) {
    throw new Error('Invalid Alibaba Cloud MCP endpoint');
  }
  return {isDomain};
}

module.exports = {installHiddenSpawn, validateEndpoint};
if (require.main === module) {
  try {
    const options = validateEndpoint(process.argv[2]);
    if (process.argv.slice(3).some(value => value !== '--silent')) throw new Error('Unsupported MCP proxy argument');
    installHiddenSpawn();
    const yunConfig = path.join(os.homedir(), '.config', 'yun');
    process.env.MCP_REMOTE_CONFIG_DIR = path.join(yunConfig, 'aliyun-domain-oauth');
    delete process.env.MCP_REMOTE_AUTH_ISSUER;
    delete process.env.MCP_REMOTE_TRUSTED_ORIGINS;
    if (options.isDomain) process.env.MCP_REMOTE_TRUSTED_ORIGINS = 'https://signin.aliyun.com,https://oauth.aliyun.com';
    const proxy = path.join(yunConfig, 'aliyun-mcp', 'node_modules', 'mcp-remote-alibaba-cloud', 'dist', 'proxy.js');
    process.argv[1] = proxy;
    if (!process.argv.includes('--silent')) process.argv.push('--silent');
    import(pathToFileURL(proxy).href).catch(() => {
      console.error('Alibaba Cloud MCP proxy could not start.');
      process.exitCode = 1;
    });
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
