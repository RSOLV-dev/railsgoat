{
  "redTests": [
    {
      "testName": "XSS via script tag injection in innerHTML",
      "testCode": "const $ = require('jquery');\nrequire('./vulnerable-code.js');\n\ntest('should prevent XSS via script tag in innerHTML', () => {\n  document.body.innerHTML = '<pre class=\"sh_javascript\">test</pre>';\n  const $pre = $('pre');\n  $pre.data('orgHtml', '<img src=x onerror=alert(1)>');\n  $pre.snippet('javascript');\n  const html = document.body.innerHTML;\n  expect(html).not.toContain('onerror');\n  expect(html).not.toContain('alert(1)');\n});",
      "attackVector": "<img src=x onerror=alert(1)>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via event handler in popup content",
      "testCode": "const $ = require('jquery');\nrequire('./vulnerable-code.js');\n\ntest('should prevent XSS in popup window content', () => {\n  const maliciousContent = '<img src=x onerror=\"alert(document.cookie)\">';\n  const spy = jest.spyOn(window, 'open').mockReturnValue({ document: { writeln: jest.fn(), close: jest.fn() } });\n  snippetPopup(maliciousContent);\n  const writeCall = spy.mock.results[0].value.document.writeln.mock.calls[0][0];\n  expect(writeCall).not.toContain('onerror');\n  spy.mockRestore();\n});",
      "attackVector": "<img src=x onerror=\"alert(document.cookie)\">",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via iframe injection in code content",
      "testCode": "const $ = require('jquery');\nrequire('./vulnerable-code.js');\n\ntest('should prevent XSS via iframe injection', () => {\n  document.body.innerHTML = '<pre class=\"sh_html\">test</pre>';\n  const $pre = $('pre');\n  $pre.data('orgHtml', '<iframe src=\"javascript:alert(1)\"></iframe>');\n  $pre.snippet('html');\n  const html = document.body.innerHTML;\n  expect(html).not.toContain('javascript:alert');\n  expect(html).not.toContain('<iframe');\n});",
      "attackVector": "<iframe src=\"javascript:alert(1)\"></iframe>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via SVG with script in code snippet",
      "testCode": "const $ = require('jquery');\nrequire('./vulnerable-code.js');\n\ntest('should prevent XSS via SVG script injection', () => {\n  document.body.innerHTML = '<pre class=\"sh_xml\">test</pre>';\n  const $pre = $('pre');\n  $pre.data('orgHtml', '<svg onload=alert(1)></svg>');\n  $pre.snippet('xml');\n  const html = document.body.innerHTML;\n  expect(html).not.toContain('onload=alert');\n  expect(html).not.toContain('<svg');\n});",
      "attackVector": "<svg onload=alert(1)></svg>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}