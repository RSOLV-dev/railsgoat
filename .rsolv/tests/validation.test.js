{
  "redTests": [
    {
      "testName": "detect hardcoded API key in source code",
      "testCode": "const fs = require('fs');\nconst path = require('path');\n\ntest('should not contain hardcoded API keys', () => {\n  const filePath = path.join(__dirname, '../demo.js');\n  const fileContent = fs.readFileSync(filePath, 'utf8');\n  const apiKeyPattern = /api_key\\s*:\\s*['\"]([a-f0-9]{32})['\"]|api_key\\s*=\\s*['\"]([a-f0-9]{32})['\"]/gi;\n  const matches = fileContent.match(apiKeyPattern);\n  expect(matches).toBeNull();\n});",
      "attackVector": "7617adae70159d09ba78cfec73c13be3",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "verify API key is loaded from environment variable",
      "testCode": "test('should use environment variable for API key', () => {\n  const fs = require('fs');\n  const path = require('path');\n  const filePath = path.join(__dirname, '../demo.js');\n  const fileContent = fs.readFileSync(filePath, 'utf8');\n  const envVarPattern = /process\\.env\\.[A-Z_]+|process\\.env\\[['\"][A-Z_]+['\"]]|getenv\\(/i;\n  const hasHardcodedKey = /api_key\\s*:\\s*['\"][a-f0-9]{32}['\"]/i.test(fileContent);\n  const usesEnvVar = envVarPattern.test(fileContent);\n  expect(hasHardcodedKey || usesEnvVar).toBe(true);\n  expect(hasHardcodedKey).toBe(false);\n});",
      "attackVector": "hardcoded_flickr_api_key",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "ensure no sensitive credentials in commented code",
      "testCode": "test('should not expose API keys even in comments', () => {\n  const fs = require('fs');\n  const path = require('path');\n  const filePath = path.join(__dirname, '../demo.js');\n  const fileContent = fs.readFileSync(filePath, 'utf8');\n  const secretPattern = /['\"]?[a-f0-9]{32}['\"]?/g;\n  const apiKeyContext = /api_key.*[a-f0-9]{32}/i;\n  const hasExposedKey = apiKeyContext.test(fileContent);\n  expect(hasExposedKey).toBe(false);\n});",
      "attackVector": "exposed_api_key_in_comments",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}