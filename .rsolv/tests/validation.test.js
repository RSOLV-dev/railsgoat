{
  "redTests": [
    {
      "testName": "test_failed_login_attempt_not_logged",
      "testCode": "require 'rails_helper'\n\nRSpec.describe SessionsController, type: :controller do\n  it 'fails when failed login is not logged' do\n    allow(Rails.logger).to receive(:warn)\n    allow(Rails.logger).to receive(:info)\n    post :create, params: { email: 'attacker@evil.com', password: 'wrong' }\n    expect(Rails.logger).to have_received(:warn).with(/failed.*login|authentication.*failed/i)\n  end\nend",
      "attackVector": "failed login with invalid credentials",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "test_successful_login_not_logged",
      "testCode": "require 'rails_helper'\n\nRSpec.describe SessionsController, type: :controller do\n  it 'fails when successful login is not logged' do\n    user = User.create!(email: 'user@test.com', password: 'password123')\n    allow(Rails.logger).to receive(:info)\n    post :create, params: { email: user.email, password: 'password123' }\n    expect(Rails.logger).to have_received(:info).with(/successful.*login|authenticated/i)\n  end\nend",
      "attackVector": "successful authentication event",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "test_logout_not_logged",
      "testCode": "require 'rails_helper'\n\nRSpec.describe SessionsController, type: :controller do\n  it 'fails when logout is not logged' do\n    user = User.create!(email: 'user@test.com', password: 'password123')\n    session[:user_id] = user.id\n    allow(Rails.logger).to receive(:info)\n    delete :destroy\n    expect(Rails.logger).to have_received(:info).with(/logout|session.*destroyed/i)\n  end\nend",
      "attackVector": "session termination event",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "test_authentication_exception_not_logged",
      "testCode": "require 'rails_helper'\n\nRSpec.describe SessionsController, type: :controller do\n  it 'fails when authentication exception is not logged' do\n    allow(User).to receive(:authenticate).and_raise(RuntimeError, 'Auth error')\n    allow(Rails.logger).to receive(:error)\n    post :create, params: { email: 'test@test.com', password: 'pass' }\n    expect(Rails.logger).to have_received(:error).with(/authentication.*error|exception/i)\n  end\nend",
      "attackVector": "authentication runtime exception",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}