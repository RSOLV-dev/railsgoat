{
  "redTests": [
    {
      "testName": "XSS via data-icon attribute with script tag",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should prevent XSS via data-icon attribute', () => {\n  const dom = new JSDOM('<!DOCTYPE html><html><body><div data-icon=\"<img src=x onerror=alert(1)>\"></div></body></html>');\n  global.window = dom.window;\n  global.document = dom.window.document;\n  \n  require('./vulnerable-code.js');\n  window.onload();\n  \n  const div = document.querySelector('div');\n  expect(div.innerHTML).not.toContain('onerror');\n  expect(div.innerHTML).not.toContain('<img');\n});",
      "attackVector": "<img src=x onerror=alert(1)>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via data-icon attribute with event handler",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should prevent XSS via data-icon with event handler', () => {\n  const dom = new JSDOM('<!DOCTYPE html><html><body><div data-icon=\"<svg onload=alert(document.cookie)>\"></div></body></html>');\n  global.window = dom.window;\n  global.document = dom.window.document;\n  \n  require('./vulnerable-code.js');\n  window.onload();\n  \n  const div = document.querySelector('div');\n  expect(div.innerHTML).not.toContain('onload');\n  expect(div.innerHTML).not.toContain('<svg');\n});",
      "attackVector": "<svg onload=alert(document.cookie)>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via className with malicious icon class",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should prevent XSS via className manipulation', () => {\n  const dom = new JSDOM('<!DOCTYPE html><html><body><div class=\"icon-home\"></div></body></html>');\n  global.window = dom.window;\n  global.document = dom.window.document;\n  \n  const icons = { 'icon-home': '<script>alert(1)</script>&#xe000;' };\n  const div = document.querySelector('div');\n  div.innerHTML = '<span>' + icons['icon-home'] + '</span>';\n  \n  expect(div.innerHTML).not.toContain('<script>');\n});",
      "attackVector": "<script>alert(1)</script>&#xe000;",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via innerHTML concatenation with existing content",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should prevent XSS when concatenating with existing innerHTML', () => {\n  const dom = new JSDOM('<!DOCTYPE html><html><body><div data-icon=\"test\"><img src=x onerror=alert(1)></div></body></html>');\n  global.window = dom.window;\n  global.document = dom.window.document;\n  \n  require('./vulnerable-code.js');\n  window.onload();\n  \n  const div = document.querySelector('div');\n  expect(div.innerHTML).not.toContain('onerror');\n});",
      "attackVector": "<img src=x onerror=alert(1)>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}