{
  "redTests": [
    {
      "testName": "detect hardcoded Flickr API key in source code",
      "testCode": "const fs = require('fs');\nconst path = require('path');\n\ntest('should not contain hardcoded API keys', () => {\n  const filePath = path.join(__dirname, '../unknown');\n  const content = fs.readFileSync(filePath, 'utf8');\n  const apiKeyPattern = /api_key\\s*:\\s*['\"]([a-f0-9]{32})['\"]|api_key\\s*=\\s*['\"]([a-f0-9]{32})['\"]|apiKey\\s*=\\s*['\"]([a-zA-Z0-9_-]+)['\"]/gi;\n  const matches = content.match(apiKeyPattern);\n  expect(matches).toBeNull();\n});",
      "attackVector": "7617adae70159d09ba78cfec73c13be3",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "verify API key is loaded from environment variable",
      "testCode": "test('should use environment variable for API key', () => {\n  const fs = require('fs');\n  const path = require('path');\n  const filePath = path.join(__dirname, '../unknown');\n  const content = fs.readFileSync(filePath, 'utf8');\n  const envVarPattern = /process\\.env\\.[A-Z_]+|process\\.env\\[['\"][A-Z_]+['\"]]|getenv\\(['\"][A-Z_]+['\"]/;\n  const hasHardcodedKey = /['\"][a-f0-9]{32}['\"]/.test(content);\n  const usesEnvVar = envVarPattern.test(content);\n  expect(hasHardcodedKey).toBe(false);\n  expect(usesEnvVar).toBe(true);\n});",
      "attackVector": "hardcoded_api_key_string",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "detect exposed Flickr API key value",
      "testCode": "test('should not expose specific Flickr API key', () => {\n  const fs = require('fs');\n  const path = require('path');\n  const filePath = path.join(__dirname, '../unknown');\n  const content = fs.readFileSync(filePath, 'utf8');\n  const exposedKey = '7617adae70159d09ba78cfec73c13be3';\n  expect(content).not.toContain(exposedKey);\n});",
      "attackVector": "7617adae70159d09ba78cfec73c13be3",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}