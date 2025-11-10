{
  "redTests": [
    {
      "testName": "XSS via innerHTML with script tag",
      "testCode": "const $ = require('jquery');\nrequire('./vulnerable-code.js');\n\ntest('should prevent XSS via innerHTML with script tag', () => {\n  document.body.innerHTML = '<pre class=\"sh_javascript\">test</pre>';\n  const $pre = $('pre');\n  $pre.snippet('javascript');\n  const malicious = '<img src=x onerror=alert(1)>';\n  $pre.html(malicious);\n  expect(document.body.innerHTML).not.toContain('onerror');\n});",
      "attackVector": "<img src=x onerror=alert(1)>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via innerHTML with event handler",
      "testCode": "const $ = require('jquery');\nrequire('./vulnerable-code.js');\n\ntest('should prevent XSS via innerHTML with event handler', () => {\n  document.body.innerHTML = '<pre class=\"sh_javascript\">test</pre>';\n  const $pre = $('pre');\n  $pre.snippet('javascript');\n  const malicious = '<div onload=alert(document.cookie)>test</div>';\n  $pre.html(malicious);\n  expect(document.body.innerHTML).not.toContain('onload=');\n});",
      "attackVector": "<div onload=alert(document.cookie)>test</div>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via innerHTML in newhtml variable",
      "testCode": "const $ = require('jquery');\nrequire('./vulnerable-code.js');\n\ntest('should prevent XSS in newhtml variable assignment', () => {\n  document.body.innerHTML = '<pre class=\"sh_javascript\"><script>alert(1)</script></pre>';\n  const $pre = $('pre');\n  $pre.snippet('javascript');\n  const html = $pre.html();\n  expect(html).not.toContain('<script>');\n});",
      "attackVector": "<script>alert(1)</script>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via innerHTML with javascript protocol",
      "testCode": "const $ = require('jquery');\nrequire('./vulnerable-code.js');\n\ntest('should prevent XSS via javascript protocol', () => {\n  document.body.innerHTML = '<pre class=\"sh_javascript\">test</pre>';\n  const $pre = $('pre');\n  $pre.snippet('javascript');\n  const malicious = '<a href=\"javascript:alert(1)\">click</a>';\n  $pre.html(malicious);\n  expect(document.body.innerHTML).not.toContain('javascript:');\n});",
      "attackVector": "<a href=\"javascript:alert(1)\">click</a>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}