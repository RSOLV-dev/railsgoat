{
  "redTests": [
    {
      "testName": "prototype_pollution_via_constructor",
      "testCode": "const $ = require('jquery');\nconst Timepicker = require('./bootstrap-timepicker');\n\ntest('should prevent prototype pollution via __proto__', () => {\n  const element = $('<input type=\"text\" />');\n  const maliciousOptions = JSON.parse('{\"__proto__\": {\"polluted\": \"true\"}}');\n  \n  element.timepicker(maliciousOptions);\n  \n  expect({}.polluted).toBeUndefined();\n  expect(Object.prototype.polluted).toBeUndefined();\n});",
      "attackVector": "{\"__proto__\": {\"polluted\": \"true\"}}",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "prototype_pollution_via_constructor_property",
      "testCode": "const $ = require('jquery');\nconst Timepicker = require('./bootstrap-timepicker');\n\ntest('should prevent prototype pollution via constructor.prototype', () => {\n  const element = $('<input type=\"text\" />');\n  const maliciousOptions = JSON.parse('{\"constructor\": {\"prototype\": {\"isAdmin\": true}}}');\n  \n  element.timepicker(maliciousOptions);\n  \n  expect({}.isAdmin).toBeUndefined();\n  expect(Object.prototype.isAdmin).toBeUndefined();\n});",
      "attackVector": "{\"constructor\": {\"prototype\": {\"isAdmin\": true}}}",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "prototype_pollution_via_data_attributes",
      "testCode": "const $ = require('jquery');\nconst Timepicker = require('./bootstrap-timepicker');\n\ntest('should prevent prototype pollution via data attributes', () => {\n  const element = $('<input type=\"text\" data-__proto__=\"{&quot;polluted&quot;:&quot;value&quot;}\" />');\n  \n  new Timepicker(element[0], {});\n  \n  expect({}.polluted).toBeUndefined();\n  expect(Object.prototype.polluted).toBeUndefined();\n});",
      "attackVector": "data-__proto__=\"{&quot;polluted&quot;:&quot;value&quot;}\"",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "prototype_pollution_via_extend_merge",
      "testCode": "const $ = require('jquery');\nconst Timepicker = require('./bootstrap-timepicker');\n\ntest('should prevent prototype pollution during options merge', () => {\n  const element = $('<input type=\"text\" />');\n  const payload = {\"__proto__\": {\"vulnerable\": \"yes\"}};\n  \n  element.timepicker(payload);\n  \n  const newObj = {};\n  expect(newObj.vulnerable).toBeUndefined();\n});",
      "attackVector": "{\"__proto__\": {\"vulnerable\": \"yes\"}}",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}