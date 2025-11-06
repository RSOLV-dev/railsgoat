{
  "redTests": [
    {
      "testName": "SQL injection via union-based attack in user id parameter",
      "testCode": "require 'rails_helper'\n\nRSpec.describe UsersController, type: :controller do\n  let(:user) { User.create!(email: 'test@example.com', password: 'password123', first_name: 'Test', last_name: 'User') }\n  \n  before { session[:user_id] = user.id }\n  \n  it 'prevents SQL injection via union attack' do\n    malicious_id = \"1' UNION SELECT id,email,password_digest,NULL,NULL,NULL,NULL,NULL FROM users WHERE '1'='1\"\n    expect {\n      patch :update, params: { user: { id: malicious_id, first_name: 'Hacked' } }, format: :json\n    }.to raise_error(ActiveRecord::StatementInvalid)\n  end\nend",
      "attackVector": "1' UNION SELECT id,email,password_digest,NULL,NULL,NULL,NULL,NULL FROM users WHERE '1'='1",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "SQL injection via boolean-based blind attack in user id parameter",
      "testCode": "require 'rails_helper'\n\nRSpec.describe UsersController, type: :controller do\n  let(:user) { User.create!(email: 'test@example.com', password: 'password123', first_name: 'Test', last_name: 'User') }\n  \n  before { session[:user_id] = user.id }\n  \n  it 'prevents SQL injection via boolean blind attack' do\n    malicious_id = \"1' OR '1'='1\"\n    expect {\n      patch :update, params: { user: { id: malicious_id, first_name: 'Hacked' } }, format: :json\n    }.to raise_error(ActiveRecord::StatementInvalid)\n  end\nend",
      "attackVector": "1' OR '1'='1",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "SQL injection via comment-based attack to bypass authentication",
      "testCode": "require 'rails_helper'\n\nRSpec.describe UsersController, type: :controller do\n  let(:user) { User.create!(email: 'test@example.com', password: 'password123', first_name: 'Test', last_name: 'User') }\n  \n  before { session[:user_id] = user.id }\n  \n  it 'prevents SQL injection via comment bypass' do\n    malicious_id = \"1' OR 1=1--\"\n    expect {\n      patch :update, params: { user: { id: malicious_id, first_name: 'Hacked' } }, format: :json\n    }.to raise_error(ActiveRecord::StatementInvalid)\n  end\nend",
      "attackVector": "1' OR 1=1--",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "SQL injection via time-based blind attack",
      "testCode": "require 'rails_helper'\n\nRSpec.describe UsersController, type: :controller do\n  let(:user) { User.create!(email: 'test@example.com', password: 'password123', first_name: 'Test', last_name: 'User') }\n  \n  before { session[:user_id] = user.id }\n  \n  it 'prevents SQL injection via time-based attack' do\n    malicious_id = \"1'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--\"\n    expect {\n      patch :update, params: { user: { id: malicious_id, first_name: 'Test' } }, format: :json\n    }.to raise_error(ActiveRecord::StatementInvalid)\n  end\nend",
      "attackVector": "1'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}