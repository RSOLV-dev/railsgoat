{
  "redTests": [
    {
      "testName": "detects hardcoded Flickr API key in source code",
      "testCode": "const fs = require('fs');\nconst path = require('path');\n\ntest('should not contain hardcoded API keys', () => {\n  const filePath = path.join(__dirname, '../vulnerable-file.js');\n  const fileContent = fs.readFileSync(filePath, 'utf8');\n  const apiKeyPattern = /api_key:\\s*['\"]([a-f0-9]{32})['\"]|api_key=([a-f0-9]{32})/gi;\n  const matches = fileContent.match(apiKeyPattern);\n  expect(matches).toBeNull();\n});",
      "attackVector": "7617adae70159d09ba78cfec73c13be3",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "verifies API key is loaded from environment variable",
      "testCode": "test('should use environment variable for API key', () => {\n  const fs = require('fs');\n  const path = require('path');\n  const filePath = path.join(__dirname, '../vulnerable-file.js');\n  const fileContent = fs.readFileSync(filePath, 'utf8');\n  const envVarPattern = /process\\.env\\.[A-Z_]+|process\\.env\\[['\"][A-Z_]+['\"]]|getenv\\(/i;\n  const hasHardcodedKey = /api_key:\\s*['\"](\\w{32})['\"]/.test(fileContent);\n  const usesEnvVar = envVarPattern.test(fileContent);\n  expect(hasHardcodedKey).toBe(false);\n  expect(usesEnvVar).toBe(true);\n});",
      "attackVector": "hardcoded_api_key_in_ajax_call",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "scans for any 32-character hexadecimal secrets",
      "testCode": "test('should not contain 32-char hex strings as API keys', () => {\n  const fs = require('fs');\n  const path = require('path');\n  const filePath = path.join(__dirname, '../vulnerable-file.js');\n  const fileContent = fs.readFileSync(filePath, 'utf8');\n  const hexSecretPattern = /['\":]\\s*['\"]?([a-f0-9]{32})['\"]?/gi;\n  const matches = [];\n  let match;\n  while ((match = hexSecretPattern.exec(fileContent)) !== null) {\n    matches.push(match[1]);\n  }\n  expect(matches.length).toBe(0);\n});",
      "attackVector": "32_character_hex_pattern",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}