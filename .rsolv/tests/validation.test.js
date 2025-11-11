{
  "redTests": [
    {
      "testName": "XSS via data-icon attribute with script tag",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should prevent XSS via data-icon attribute', () => {\n  const dom = new JSDOM('<!DOCTYPE html><html><body><span data-icon=\"test\"></span></body></html>');\n  global.document = dom.window.document;\n  global.window = dom.window;\n  \n  const el = document.querySelector('[data-icon]');\n  el.setAttribute('data-icon', '<img src=x onerror=alert(1)>');\n  \n  require('./vulnerable-code.js');\n  \n  expect(el.innerHTML).not.toContain('<img');\n  expect(el.innerHTML).not.toContain('onerror');\n});",
      "attackVector": "<img src=x onerror=alert(1)>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via existing innerHTML with malicious content",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should prevent XSS via existing innerHTML', () => {\n  const dom = new JSDOM('<!DOCTYPE html><html><body><span class=\"icon-home\"><script>alert(1)</script></span></body></html>');\n  global.document = dom.window.document;\n  global.window = dom.window;\n  \n  require('./vulnerable-code.js');\n  \n  const el = document.querySelector('.icon-home');\n  expect(el.innerHTML).not.toContain('<script>');\n  expect(el.querySelectorAll('script').length).toBe(0);\n});",
      "attackVector": "<script>alert(1)</script>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via data-icon with event handler injection",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should prevent XSS via event handler in data-icon', () => {\n  const dom = new JSDOM('<!DOCTYPE html><html><body><div data-icon=\"test\"></div></body></html>');\n  global.document = dom.window.document;\n  global.window = dom.window;\n  \n  const el = document.querySelector('[data-icon]');\n  el.setAttribute('data-icon', '\" onload=\"alert(1)\"');\n  \n  require('./vulnerable-code.js');\n  \n  expect(el.innerHTML).not.toContain('onload');\n  expect(el.innerHTML).not.toContain('alert');\n});",
      "attackVector": "\" onload=\"alert(1)\"",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via innerHTML with iframe injection",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should prevent XSS via iframe injection', () => {\n  const dom = new JSDOM('<!DOCTYPE html><html><body><span class=\"icon-home\"><iframe src=\"javascript:alert(1)\"></iframe></span></body></html>');\n  global.document = dom.window.document;\n  global.window = dom.window;\n  \n  require('./vulnerable-code.js');\n  \n  const el = document.querySelector('.icon-home');\n  expect(el.innerHTML).not.toContain('<iframe');\n  expect(el.querySelectorAll('iframe').length).toBe(0);\n});",
      "attackVector": "<iframe src=\"javascript:alert(1)\"></iframe>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}