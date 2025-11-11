{
  "redTests": [
    {
      "testName": "XSS via script tag injection in code content",
      "testCode": "const $ = require('jquery');\nrequire('./vulnerable-code.js');\n\ndescribe('XSS via innerHTML - script injection', () => {\n  it('should fail: executes injected script', () => {\n    document.body.innerHTML = '<pre id=\"test\"></pre>';\n    const $pre = $('#test');\n    $pre.html('<script>window.xssExecuted=true;</script>');\n    $pre.snippet('javascript');\n    expect(window.xssExecuted).toBeUndefined();\n  });\n});",
      "attackVector": "<script>window.xssExecuted=true;</script>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via img onerror event handler",
      "testCode": "const $ = require('jquery');\nrequire('./vulnerable-code.js');\n\ndescribe('XSS via innerHTML - img onerror', () => {\n  it('should fail: executes onerror handler', () => {\n    document.body.innerHTML = '<pre id=\"test\"></pre>';\n    const $pre = $('#test');\n    $pre.html('<img src=x onerror=\"window.imgXSS=1\">');\n    $pre.snippet('javascript');\n    expect(window.imgXSS).toBeUndefined();\n  });\n});",
      "attackVector": "<img src=x onerror=\"window.imgXSS=1\">",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via iframe with javascript URL",
      "testCode": "const $ = require('jquery');\nrequire('./vulnerable-code.js');\n\ndescribe('XSS via innerHTML - iframe javascript', () => {\n  it('should fail: executes javascript in iframe', () => {\n    document.body.innerHTML = '<pre id=\"test\"></pre>';\n    const $pre = $('#test');\n    $pre.html('<iframe src=\"javascript:window.iframeXSS=1\"></iframe>');\n    $pre.snippet('javascript');\n    expect(window.iframeXSS).toBeUndefined();\n  });\n});",
      "attackVector": "<iframe src=\"javascript:window.iframeXSS=1\"></iframe>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via SVG with onload event",
      "testCode": "const $ = require('jquery');\nrequire('./vulnerable-code.js');\n\ndescribe('XSS via innerHTML - SVG onload', () => {\n  it('should fail: executes SVG onload event', () => {\n    document.body.innerHTML = '<pre id=\"test\"></pre>';\n    const $pre = $('#test');\n    $pre.html('<svg onload=\"window.svgXSS=1\"></svg>');\n    $pre.snippet('javascript');\n    expect(window.svgXSS).toBeUndefined();\n  });\n});",
      "attackVector": "<svg onload=\"window.svgXSS=1\"></svg>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}