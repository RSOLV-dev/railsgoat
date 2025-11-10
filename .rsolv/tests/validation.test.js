{
  "redTests": [
    {
      "testName": "XSS via document.write in snippetPopup with script injection",
      "testCode": "test('should be vulnerable to XSS via document.write with script tag', () => {\n  const maliciousContent = '<script>window.xssExecuted=true;</script>';\n  const mockWindow = { document: { writeln: jest.fn(), close: jest.fn() }, focus: jest.fn() };\n  global.window.open = jest.fn(() => mockWindow);\n  \n  snippetPopup(maliciousContent);\n  \n  const writtenContent = mockWindow.document.writeln.mock.calls.join('');\n  expect(writtenContent).toContain('<script>window.xssExecuted=true;</script>');\n  expect(mockWindow.document.writeln).toHaveBeenCalled();\n});",
      "attackVector": "<script>window.xssExecuted=true;</script>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via document.write with event handler injection",
      "testCode": "test('should be vulnerable to XSS via document.write with event handler', () => {\n  const maliciousContent = '<img src=x onerror=\"alert(1)\">';\n  const mockWindow = { document: { writeln: jest.fn(), close: jest.fn() }, focus: jest.fn() };\n  global.window.open = jest.fn(() => mockWindow);\n  \n  snippetPopup(maliciousContent);\n  \n  const writtenContent = mockWindow.document.writeln.mock.calls.join('');\n  expect(writtenContent).toContain('onerror=\"alert(1)\"');\n  expect(mockWindow.document.writeln).toHaveBeenCalled();\n});",
      "attackVector": "<img src=x onerror=\"alert(1)\">",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via document.write with iframe injection",
      "testCode": "test('should be vulnerable to XSS via document.write with iframe', () => {\n  const maliciousContent = '<iframe src=\"javascript:alert(document.domain)\"></iframe>';\n  const mockWindow = { document: { writeln: jest.fn(), close: jest.fn() }, focus: jest.fn() };\n  global.window.open = jest.fn(() => mockWindow);\n  \n  snippetPopup(maliciousContent);\n  \n  const writtenContent = mockWindow.document.writeln.mock.calls.join('');\n  expect(writtenContent).toContain('javascript:alert(document.domain)');\n  expect(mockWindow.document.writeln).toHaveBeenCalled();\n});",
      "attackVector": "<iframe src=\"javascript:alert(document.domain)\"></iframe>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}