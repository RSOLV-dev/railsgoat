{
  "redTests": [
    {
      "testName": "XSS via document.write in snippetPopup with script injection",
      "testCode": "test('XSS via document.write with script tag', () => {\n  const maliciousContent = '<script>window.xssExecuted=true;</script>';\n  const mockWindow = { document: { writeln: jest.fn(), close: jest.fn() }, focus: jest.fn() };\n  window.open = jest.fn(() => mockWindow);\n  \n  snippetPopup(maliciousContent);\n  \n  const writtenContent = mockWindow.document.writeln.mock.calls.join('');\n  expect(writtenContent).toContain('<script>window.xssExecuted=true;</script>');\n  expect(writtenContent).toMatch(/<script>.*<\\/script>/);\n});",
      "attackVector": "<script>window.xssExecuted=true;</script>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via document.write with img onerror payload",
      "testCode": "test('XSS via document.write with img onerror', () => {\n  const maliciousContent = '<img src=x onerror=\"alert(1)\">';\n  const mockWindow = { document: { writeln: jest.fn(), close: jest.fn() }, focus: jest.fn() };\n  window.open = jest.fn(() => mockWindow);\n  \n  snippetPopup(maliciousContent);\n  \n  const writtenContent = mockWindow.document.writeln.mock.calls.join('');\n  expect(writtenContent).toContain('onerror=\"alert(1)\"');\n  expect(writtenContent).toMatch(/onerror\\s*=/);\n});",
      "attackVector": "<img src=x onerror=\"alert(1)\">",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via document.write with event handler injection",
      "testCode": "test('XSS via document.write with onload handler', () => {\n  const maliciousContent = '<body onload=\"document.location=\\'http://evil.com\\'\"></body>';\n  const mockWindow = { document: { writeln: jest.fn(), close: jest.fn() }, focus: jest.fn() };\n  window.open = jest.fn(() => mockWindow);\n  \n  snippetPopup(maliciousContent);\n  \n  const writtenContent = mockWindow.document.writeln.mock.calls.join('');\n  expect(writtenContent).toContain('onload=');\n  expect(writtenContent).toMatch(/onload\\s*=.*document\\.location/);\n});",
      "attackVector": "<body onload=\"document.location='http://evil.com'\"></body>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}