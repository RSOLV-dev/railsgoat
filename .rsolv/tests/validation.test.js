{
  "redTests": [
    {
      "testName": "XSS via document.write with script injection",
      "testCode": "const maliciousContent = '<script>alert(\"XSS\")</script>';\nconst mockWindow = { document: { write: jest.fn(), writeln: jest.fn(), close: jest.fn() } };\nglobal.top = { consoleRef: mockWindow };\nsnippetPopup(maliciousContent);\nconst writtenContent = mockWindow.document.writeln.mock.calls.join('');\nexpect(writtenContent).toContain('<script>alert(\"XSS\")</script>');\nexpect(writtenContent).not.toContain('&lt;script&gt;');",
      "attackVector": "<script>alert(\"XSS\")</script>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via document.write with img onerror",
      "testCode": "const maliciousContent = '<img src=x onerror=\"alert(1)\">';\nconst mockWindow = { document: { write: jest.fn(), writeln: jest.fn(), close: jest.fn() } };\nglobal.top = { consoleRef: mockWindow };\nsnippetPopup(maliciousContent);\nconst writtenContent = mockWindow.document.writeln.mock.calls.join('');\nexpect(writtenContent).toContain('onerror=\"alert(1)\"');\nexpect(writtenContent).not.toContain('onerror=&quot;');",
      "attackVector": "<img src=x onerror=\"alert(1)\">",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via document.write with iframe injection",
      "testCode": "const maliciousContent = '<iframe src=\"javascript:alert(1)\"></iframe>';\nconst mockWindow = { document: { write: jest.fn(), writeln: jest.fn(), close: jest.fn() } };\nglobal.top = { consoleRef: mockWindow };\nsnippetPopup(maliciousContent);\nconst writtenContent = mockWindow.document.writeln.mock.calls.join('');\nexpect(writtenContent).toContain('javascript:alert(1)');\nexpect(writtenContent).not.toContain('&lt;iframe');",
      "attackVector": "<iframe src=\"javascript:alert(1)\"></iframe>",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "XSS via document.write with event handler",
      "testCode": "const maliciousContent = '<body onload=\"alert(document.cookie)\">';\nconst mockWindow = { document: { write: jest.fn(), writeln: jest.fn(), close: jest.fn() } };\nglobal.top = { consoleRef: mockWindow };\nsnippetPopup(maliciousContent);\nconst writtenContent = mockWindow.document.writeln.mock.calls.join('');\nexpect(writtenContent).toContain('onload=\"alert(document.cookie)\"');\nexpect(writtenContent).not.toContain('&lt;body');",
      "attackVector": "<body onload=\"alert(document.cookie)\">",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}