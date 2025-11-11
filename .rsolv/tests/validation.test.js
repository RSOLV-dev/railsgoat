{
  "redTests": [
    {
      "testName": "XSS via data-icon attribute with script tag",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should prevent XSS via data-icon attribute', () => {\n  const dom = new JSDOM('<!DOCTYPE html><html><body><span data-icon=\"test\"></span></body></html>');\n  global.document = dom.window.document;\n  global.window = dom.window;\n  \n  const el = document.querySelector('[data-icon]');\n  el.setAttribute('data-icon', '<img src=x onerror=alert(1)>');\n  \n  require('./vulnerable-code.js');\n  \n  expect(el.innerHTML).not.toContain('onerror');\n  expect(el.innerHTML).not.toContain('<img');\n});",
      "attackVector": "<img src=x onerror=alert(1)>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via className with malicious HTML",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should prevent XSS via icon className', () => {\n  const dom = new JSDOM('<!DOCTYPE html><html><body><div class=\"icon-home\"></div></body></html>');\n  global.document = dom.window.document;\n  global.window = dom.window;\n  \n  const el = document.querySelector('.icon-home');\n  el.innerHTML = '<script>alert(\"XSS\")</script>Original';\n  \n  require('./vulnerable-code.js');\n  \n  expect(el.innerHTML).not.toContain('<script>');\n  expect(el.innerHTML).not.toContain('alert');\n});",
      "attackVector": "<script>alert(\"XSS\")</script>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via innerHTML concatenation with event handler",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should prevent XSS via innerHTML concatenation', () => {\n  const dom = new JSDOM('<!DOCTYPE html><html><body><span data-icon=\"&#xe000;\"></span></body></html>');\n  global.document = dom.window.document;\n  global.window = dom.window;\n  \n  const el = document.querySelector('[data-icon]');\n  el.innerHTML = '<img src=x onload=alert(document.cookie)>';\n  \n  require('./vulnerable-code.js');\n  \n  expect(el.innerHTML).not.toContain('onload');\n  expect(el.innerHTML).not.toContain('document.cookie');\n});",
      "attackVector": "<img src=x onload=alert(document.cookie)>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via SVG with embedded script",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should prevent XSS via SVG injection', () => {\n  const dom = new JSDOM('<!DOCTYPE html><html><body><div class=\"icon-home\"></div></body></html>');\n  global.document = dom.window.document;\n  global.window = dom.window;\n  \n  const el = document.querySelector('.icon-home');\n  el.innerHTML = '<svg onload=alert(1)><circle/></svg>';\n  \n  require('./vulnerable-code.js');\n  \n  expect(el.innerHTML).not.toContain('onload=alert');\n  expect(el.innerHTML).not.toContain('<svg');\n});",
      "attackVector": "<svg onload=alert(1)><circle/></svg>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}