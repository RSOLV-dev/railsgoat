{
  "redTests": [
    {
      "testName": "XSS via script tag injection in code content",
      "testCode": "const $ = require('jquery');\nrequire('./vulnerable-code.js');\n\ntest('should allow XSS via script tag in innerHTML', () => {\n  document.body.innerHTML = '<pre id=\"test-pre\"></pre>';\n  const $pre = $('#test-pre');\n  const maliciousCode = '<script>window.xssExecuted=true;</script>';\n  $pre.html(maliciousCode);\n  $pre.snippet('javascript');\n  const html = $pre.parent().html();\n  expect(html).toContain('<script>');\n  expect(html).toContain('xssExecuted');\n});",
      "attackVector": "<script>window.xssExecuted=true;</script>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via img onerror event handler",
      "testCode": "const $ = require('jquery');\nrequire('./vulnerable-code.js');\n\ntest('should allow XSS via img onerror', () => {\n  document.body.innerHTML = '<pre id=\"test-pre\"></pre>';\n  const $pre = $('#test-pre');\n  const maliciousCode = '<img src=x onerror=\"alert(1)\">';\n  $pre.html(maliciousCode);\n  $pre.snippet('javascript');\n  const html = $pre.parent().html();\n  expect(html).toContain('onerror');\n  expect(html).toContain('alert');\n});",
      "attackVector": "<img src=x onerror=\"alert(1)\">",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via javascript protocol in anchor tag",
      "testCode": "const $ = require('jquery');\nrequire('./vulnerable-code.js');\n\ntest('should allow XSS via javascript protocol', () => {\n  document.body.innerHTML = '<pre id=\"test-pre\"></pre>';\n  const $pre = $('#test-pre');\n  const maliciousCode = '<a href=\"javascript:alert(1)\">click</a>';\n  $pre.html(maliciousCode);\n  $pre.snippet('javascript');\n  const html = $pre.parent().html();\n  expect(html).toContain('javascript:');\n  expect(html).toContain('alert');\n});",
      "attackVector": "<a href=\"javascript:alert(1)\">click</a>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via iframe with malicious src",
      "testCode": "const $ = require('jquery');\nrequire('./vulnerable-code.js');\n\ntest('should allow XSS via iframe injection', () => {\n  document.body.innerHTML = '<pre id=\"test-pre\"></pre>';\n  const $pre = $('#test-pre');\n  const maliciousCode = '<iframe src=\"javascript:alert(1)\"></iframe>';\n  $pre.html(maliciousCode);\n  $pre.snippet('javascript');\n  const html = $pre.parent().html();\n  expect(html).toContain('<iframe');\n  expect(html).toContain('javascript:');\n});",
      "attackVector": "<iframe src=\"javascript:alert(1)\"></iframe>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via SVG with onload event",
      "testCode": "const $ = require('jquery');\nrequire('./vulnerable-code.js');\n\ntest('should allow XSS via SVG onload', () => {\n  document.body.innerHTML = '<pre id=\"test-pre\"></pre>';\n  const $pre = $('#test-pre');\n  const maliciousCode = '<svg onload=\"alert(1)\">';\n  $pre.html(maliciousCode);\n  $pre.snippet('javascript');\n  const html = $pre.parent().html();\n  expect(html).toContain('<svg');\n  expect(html).toContain('onload');\n});",
      "attackVector": "<svg onload=\"alert(1)\">",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}