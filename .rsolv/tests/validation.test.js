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
      "testCode": "require 'rails_helper'\n\nRSpec.describe Benefits, type: :model do\n  it 'prevents command injection via backticks' do\n    file = double('file', original_filename: 'test`whoami`.txt', read: 'data')\n    allow(File).to receive(:open).and_yield(double(write: nil, close: nil))\n    allow(File).to receive(:exist?).and_return(true)\n    expect { Benefits.save(file, 'true') }.not_to raise_error\n    expect(file.original_filename).not_to match(/root|ubuntu|admin/)\n  end\nend",
      "attackVector": "test`whoami`.txt",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "command injection via pipe operator in filename",
      "testCode": "require 'rails_helper'\n\nRSpec.describe Benefits, type: :model do\n  it 'prevents command injection via pipe operator' do\n    file = double('file', original_filename: 'test.txt | cat /etc/passwd', read: 'data')\n    allow(File).to receive(:open).and_yield(double(write: nil, close: nil))\n    allow(File).to receive(:exist?).and_return(true)\n    allow(Benefits).to receive(:system)\n    Benefits.save(file, 'true')\n    expect(Benefits).to have_received(:system).with(/cat \\/etc\\/passwd/).never\n  end\nend",
      "attackVector": "test.txt | cat /etc/passwd",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "command injection via dollar sign command substitution",
      "testCode": "require 'rails_helper'\n\nRSpec.describe Benefits, type: :model do\n  it 'prevents command injection via dollar sign substitution' do\n    file = double('file', original_filename: 'test$(id).txt', read: 'data')\n    allow(File).to receive(:open).and_yield(double(write: nil, close: nil))\n    allow(File).to receive(:exist?).and_return(true)\n    allow(Benefits).to receive(:system).and_call_original\n    Benefits.save(file, 'true')\n    expect(file.original_filename).to eq('test$(id).txt')\n  end\nend",
      "attackVector": "test$(id).txt",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}