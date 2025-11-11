{
  "redTests": [
    {
      "testName": "XSS via data-icon attribute with script tag",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should prevent XSS via data-icon attribute', () => {\n  const dom = new JSDOM('<!DOCTYPE html><html><body><span data-icon=\"<img src=x onerror=alert(1)>\"></span></body></html>');\n  global.window = dom.window;\n  global.document = dom.window.document;\n  \n  require('./vulnerable-code.js');\n  window.onload();\n  \n  const span = document.querySelector('span');\n  const hasXSS = span.innerHTML.includes('<img') && span.innerHTML.includes('onerror');\n  expect(hasXSS).toBe(false);\n});",
      "attackVector": "<img src=x onerror=alert(1)>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via icon class with malicious entity",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should prevent XSS via manipulated icon class', () => {\n  const dom = new JSDOM('<!DOCTYPE html><html><body><div class=\"icon-home\"></div></body></html>');\n  global.window = dom.window;\n  global.document = dom.window.document;\n  \n  const originalHTML = '<script>alert(\"XSS\")</script>test';\n  document.querySelector('div').innerHTML = originalHTML;\n  \n  require('./vulnerable-code.js');\n  window.onload();\n  \n  const div = document.querySelector('div');\n  const hasScript = div.querySelector('script') !== null;\n  expect(hasScript).toBe(false);\n});",
      "attackVector": "<script>alert(\"XSS\")</script>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via innerHTML concatenation with existing malicious content",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should sanitize existing innerHTML before concatenation', () => {\n  const dom = new JSDOM('<!DOCTYPE html><html><body><span data-icon=\"test\"><img src=x onerror=alert(1)></span></body></html>');\n  global.window = dom.window;\n  global.document = dom.window.document;\n  \n  require('./vulnerable-code.js');\n  window.onload();\n  \n  const span = document.querySelector('span');\n  const hasXSS = span.innerHTML.includes('onerror');\n  expect(hasXSS).toBe(false);\n});",
      "attackVector": "<img src=x onerror=alert(1)>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via event handler in data-icon attribute",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should prevent XSS via event handler injection', () => {\n  const dom = new JSDOM('<!DOCTYPE html><html><body><div data-icon=\"<div onmouseover=alert(1)>hover</div>\"></div></body></html>');\n  global.window = dom.window;\n  global.document = dom.window.document;\n  \n  require('./vulnerable-code.js');\n  window.onload();\n  \n  const div = document.querySelector('div');\n  const hasEventHandler = div.innerHTML.includes('onmouseover');\n  expect(hasEventHandler).toBe(false);\n});",
      "attackVector": "<div onmouseover=alert(1)>hover</div>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}