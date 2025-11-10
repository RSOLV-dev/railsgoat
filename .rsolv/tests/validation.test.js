{
  "redTests": [
    {
      "testName": "command injection via semicolon in filename",
      "testCode": "require 'rails_helper'\n\nRSpec.describe Benefits, type: :model do\n  it 'prevents command injection via semicolon' do\n    file = double('file', original_filename: 'test.txt; touch /tmp/pwned', read: 'data')\n    allow(File).to receive(:open).and_yield(double(write: nil, close: nil))\n    allow(File).to receive(:exist?).and_return(true)\n    expect(self).to receive(:system).with(/touch \\/tmp\\/pwned/)\n    Benefits.save(file, 'true')\n  end\nend",
      "attackVector": "test.txt; touch /tmp/pwned",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "command injection via backticks in filename",
      "testCode": "require 'rails_helper'\n\nRSpec.describe Benefits, type: :model do\n  it 'prevents command injection via backticks' do\n    file = double('file', original_filename: 'test`whoami`.txt', read: 'data')\n    allow(File).to receive(:open).and_yield(double(write: nil, close: nil))\n    allow(File).to receive(:exist?).and_return(true)\n    expect(self).to receive(:system).with(/`whoami`/)\n    Benefits.save(file, 'true')\n  end\nend",
      "attackVector": "test`whoami`.txt",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "command injection via pipe operator in filename",
      "testCode": "require 'rails_helper'\n\nRSpec.describe Benefits, type: :model do\n  it 'prevents command injection via pipe' do\n    file = double('file', original_filename: 'test.txt | cat /etc/passwd', read: 'data')\n    allow(File).to receive(:open).and_yield(double(write: nil, close: nil))\n    allow(File).to receive(:exist?).and_return(true)\n    expect(self).to receive(:system).with(/cat \\/etc\\/passwd/)\n    Benefits.save(file, 'true')\n  end\nend",
      "attackVector": "test.txt | cat /etc/passwd",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "command injection via dollar sign command substitution",
      "testCode": "require 'rails_helper'\n\nRSpec.describe Benefits, type: :model do\n  it 'prevents command injection via dollar substitution' do\n    file = double('file', original_filename: 'test$(id).txt', read: 'data')\n    allow(File).to receive(:open).and_yield(double(write: nil, close: nil))\n    allow(File).to receive(:exist?).and_return(true)\n    expect(self).to receive(:system).with(/\\$\\(id\\)/)\n    Benefits.save(file, 'true')\n  end\nend",
      "attackVector": "test$(id).txt",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}