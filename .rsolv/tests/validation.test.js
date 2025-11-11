{
  "redTests": [
    {
      "testName": "XSS via data-icon attribute with script tag",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should be vulnerable to XSS via data-icon attribute', () => {\n  const dom = new JSDOM(`<html><body><div data-icon=\"<img src=x onerror=alert('XSS')>\"></div></body></html>`);\n  global.window = dom.window;\n  global.document = dom.window.document;\n  \n  require('./vulnerable-code.js');\n  window.onload();\n  \n  const html = document.body.innerHTML;\n  expect(html).toContain('onerror');\n  expect(html).toContain('alert');\n});",
      "attackVector": "<img src=x onerror=alert('XSS')>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via data-icon attribute with event handler",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should be vulnerable to XSS via onload event', () => {\n  const dom = new JSDOM(`<html><body><div data-icon=\"<svg/onload=alert(1)>\"></div></body></html>`);\n  global.window = dom.window;\n  global.document = dom.window.document;\n  \n  require('./vulnerable-code.js');\n  window.onload();\n  \n  const html = document.body.innerHTML;\n  expect(html).toContain('onload');\n  expect(html).toContain('svg');\n});",
      "attackVector": "<svg/onload=alert(1)>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via malicious icon class name",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should be vulnerable to XSS via className manipulation', () => {\n  const maliciousHTML = `<html><body><div class=\"icon-home\"></div></body></html>`;\n  const dom = new JSDOM(maliciousHTML);\n  global.window = dom.window;\n  global.document = dom.window.document;\n  \n  const originalInnerHTML = document.querySelector('div').innerHTML;\n  require('./vulnerable-code.js');\n  window.onload();\n  \n  const modifiedHTML = document.querySelector('div').innerHTML;\n  expect(modifiedHTML).not.toBe(originalInnerHTML);\n  expect(modifiedHTML).toContain('icomoon');\n});",
      "attackVector": "&#xe000; with innerHTML manipulation",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via script injection in data-icon",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should be vulnerable to script injection', () => {\n  const dom = new JSDOM(`<html><body><div data-icon=\"<script>alert('XSS')</script>\"></div></body></html>`);\n  global.window = dom.window;\n  global.document = dom.window.document;\n  \n  require('./vulnerable-code.js');\n  window.onload();\n  \n  const html = document.body.innerHTML;\n  expect(html).toContain('<script>');\n  expect(html).toContain('alert');\n});",
      "attackVector": "<script>alert('XSS')</script>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via iframe injection",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should be vulnerable to iframe injection', () => {\n  const dom = new JSDOM(`<html><body><div data-icon=\"<iframe src=javascript:alert('XSS')></iframe>\"></div></body></html>`);\n  global.window = dom.window;\n  global.document = dom.window.document;\n  \n  require('./vulnerable-code.js');\n  window.onload();\n  \n  const html = document.body.innerHTML;\n  expect(html).toContain('iframe');\n  expect(html).toContain('javascript:');\n});",
      "attackVector": "<iframe src=javascript:alert('XSS')></iframe>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}