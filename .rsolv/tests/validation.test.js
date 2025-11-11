{
  "redTests": [
    {
      "testName": "prototype_pollution_via_constructor",
      "testCode": "const $ = require('jquery');\nconst pollutedObj = {};\nconst maliciousOptions = JSON.parse('{\"constructor\": {\"prototype\": {\"polluted\": \"true\"}}}');\n$.fn.timepicker.defaults = $.extend({}, $.fn.timepicker.defaults, maliciousOptions);\nconst testObj = {};\nexpect(testObj.polluted).toBeUndefined();",
      "attackVector": "{\"constructor\": {\"prototype\": {\"polluted\": \"true\"}}}",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "prototype_pollution_via___proto__",
      "testCode": "const $ = require('jquery');\nconst maliciousOptions = JSON.parse('{\"__proto__\": {\"isAdmin\": true}}');\nconst $element = $('<input type=\"text\">');\n$element.data('minuteStep', 15);\n$element.data('__proto__', {isAdmin: true});\nconst testObj = {};\nexpect(testObj.isAdmin).toBeUndefined();",
      "attackVector": "{\"__proto__\": {\"isAdmin\": true}}",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "prototype_pollution_via_options_extend",
      "testCode": "const $ = require('jquery');\nconst $element = $('<input type=\"text\">');\nconst maliciousData = {'__proto__': {polluted: 'yes'}};\n$element.data('__proto__', {polluted: 'yes'});\nconst timepicker = new $.fn.timepicker.Constructor($element[0], {});\nconst cleanObj = {};\nexpect(cleanObj.polluted).toBeUndefined();",
      "attackVector": "{'__proto__': {polluted: 'yes'}}",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "prototype_pollution_via_data_attributes",
      "testCode": "const $ = require('jquery');\nconst $element = $('<input type=\"text\" data-__proto__=\"{&quot;hacked&quot;:true}\">');\n$element.attr('data-constructor', '{\"prototype\":{\"vulnerable\":true}}');\nconst options = $element.data();\nconst timepicker = new $.fn.timepicker.Constructor($element[0], options);\nconst testObj = {};\nexpect(testObj.hacked).toBeUndefined();\nexpect(testObj.vulnerable).toBeUndefined();",
      "attackVector": "data-__proto__=\"{&quot;hacked&quot;:true}\"",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}