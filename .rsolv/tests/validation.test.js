{
  "redTests": [
    {
      "testName": "ReDoS attack via rgba percentage format with nested quantifiers",
      "testCode": "const Color = require('./bootstrap-colorpicker');\n\ntest('ReDoS via rgba percentage format', () => {\n  const maliciousInput = 'rgba(' + '1.'.repeat(50) + '%, ' + '1.'.repeat(50) + '%, ' + '1.'.repeat(50) + '%, 1)';\n  const startTime = Date.now();\n  \n  try {\n    new Color(maliciousInput);\n  } catch (e) {}\n  \n  const executionTime = Date.now() - startTime;\n  expect(executionTime).toBeLessThan(100);\n}, 200);",
      "attackVector": "rgba(1.1.1.1.1.1.1.1.1.1.%, 1.1.1.1.1.1.1.1.1.1.%, 1.1.1.1.1.1.1.1.1.1.%, 1)",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "ReDoS attack via hsla format with nested quantifiers",
      "testCode": "const Color = require('./bootstrap-colorpicker');\n\ntest('ReDoS via hsla format', () => {\n  const maliciousInput = 'hsla(' + '1.'.repeat(50) + ', ' + '1.'.repeat(50) + '%, ' + '1.'.repeat(50) + '%, 1)';\n  const startTime = Date.now();\n  \n  try {\n    new Color(maliciousInput);\n  } catch (e) {}\n  \n  const executionTime = Date.now() - startTime;\n  expect(executionTime).toBeLessThan(100);\n}, 200);",
      "attackVector": "hsla(1.1.1.1.1.1.1.1.1.1., 1.1.1.1.1.1.1.1.1.1.%, 1.1.1.1.1.1.1.1.1.1.%, 1)",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "ReDoS attack via rgb format with nested quantifiers",
      "testCode": "const Color = require('./bootstrap-colorpicker');\n\ntest('ReDoS via rgb format', () => {\n  const maliciousInput = 'rgb(' + '1'.repeat(100) + ', ' + '1'.repeat(100) + ', ' + '1'.repeat(100) + ')';\n  const startTime = Date.now();\n  \n  try {\n    new Color(maliciousInput);\n  } catch (e) {}\n  \n  const executionTime = Date.now() - startTime;\n  expect(executionTime).toBeLessThan(100);\n}, 200);",
      "attackVector": "rgb(111111111111111111111111111111, 111111111111111111111111111111, 111111111111111111111111111111)",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}