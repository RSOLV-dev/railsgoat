{
  "red": {
    "testName": "ReDoS attack via nested quantifiers in className regex",
    "testCode": "describe('ReDoS Vulnerability Test', () => {\n  it('should timeout on malicious className input with nested quantifiers', () => {\n    const maliciousClassName = 'icon-' + 'a'.repeat(30) + '!';\n    const mockElement = { className: maliciousClassName, innerHTML: '', getAttribute: () => null };\n    const startTime = Date.now();\n    const regex = /icon-[^\\s'\"]+/;\n    regex.exec(mockElement.className);\n    const executionTime = Date.now() - startTime;\n    expect(executionTime).toBeLessThan(100);\n  });\n});",
    "attackVector": "icon-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!",
    "expectedBehavior": "should_fail_on_vulnerable_code"
  }
}