{
  "redTests": [
    {
      "testName": "XSS via script tag injection in data-icon attribute",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should prevent XSS via script tag in data-icon', () => {\n  const dom = new JSDOM(`<div data-icon=\"<script>window.xssExecuted=true</script>\"></div>`);\n  global.window = dom.window;\n  global.document = dom.window.document;\n  \n  require('./vulnerable-code.js');\n  window.onload();\n  \n  expect(dom.window.xssExecuted).toBeUndefined();\n  expect(document.querySelector('script')).toBeNull();\n});",
      "attackVector": "<script>window.xssExecuted=true</script>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via img onerror event handler",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should prevent XSS via img onerror', () => {\n  const dom = new JSDOM(`<div data-icon='<img src=x onerror=\"window.xssTriggered=true\">'></div>`);\n  global.window = dom.window;\n  global.document = dom.window.document;\n  \n  require('./vulnerable-code.js');\n  window.onload();\n  \n  expect(dom.window.xssTriggered).toBeUndefined();\n});",
      "attackVector": "<img src=x onerror=\"window.xssTriggered=true\">",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via iframe injection",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should prevent XSS via iframe injection', () => {\n  const dom = new JSDOM(`<div data-icon='<iframe src=\"javascript:alert(1)\"></iframe>'></div>`);\n  global.window = dom.window;\n  global.document = dom.window.document;\n  \n  require('./vulnerable-code.js');\n  window.onload();\n  \n  expect(document.querySelector('iframe')).toBeNull();\n});",
      "attackVector": "<iframe src=\"javascript:alert(1)\"></iframe>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via event handler in HTML attribute",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should prevent XSS via onclick handler', () => {\n  const dom = new JSDOM(`<div data-icon='<div onclick=\"window.clickXSS=true\">click</div>'></div>`);\n  global.window = dom.window;\n  global.document = dom.window.document;\n  \n  require('./vulnerable-code.js');\n  window.onload();\n  \n  const injectedDiv = document.querySelector('[onclick]');\n  expect(injectedDiv).toBeNull();\n});",
      "attackVector": "<div onclick=\"window.clickXSS=true\">click</div>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via SVG with embedded script",
      "testCode": "const { JSDOM } = require('jsdom');\n\ntest('should prevent XSS via SVG script', () => {\n  const dom = new JSDOM(`<div data-icon='<svg><script>window.svgXSS=true</script></svg>'></div>`);\n  global.window = dom.window;\n  global.document = dom.window.document;\n  \n  require('./vulnerable-code.js');\n  window.onload();\n  \n  expect(dom.window.svgXSS).toBeUndefined();\n  expect(document.querySelector('svg script')).toBeNull();\n});",
      "attackVector": "<svg><script>window.svgXSS=true</script></svg>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}