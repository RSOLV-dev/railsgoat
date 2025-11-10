{
  "redTests": [
    {
      "testName": "test_generate_token_uses_md5_algorithm",
      "testCode": "require 'rails_helper'\n\nRSpec.describe PasswordResetsController, type: :controller do\n  it 'fails when MD5 is used for token generation' do\n    controller_instance = PasswordResetsController.new\n    token = controller_instance.send(:generate_token, 1, 'test@example.com')\n    md5_hash = Digest::MD5.hexdigest('test@example.com')\n    expect(token).not_to include(md5_hash)\n  end\nend",
      "attackVector": "MD5 hash collision attack on password reset tokens",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "test_is_valid_uses_md5_for_verification",
      "testCode": "require 'rails_helper'\n\nRSpec.describe PasswordResetsController, type: :controller do\n  it 'fails when MD5 is used for token validation' do\n    user = User.create!(email: 'victim@example.com', password: 'password123')\n    controller_instance = PasswordResetsController.new\n    allow(User).to receive(:find_by).and_return(user)\n    token = \"#{user.id}-#{Digest::MD5.hexdigest(user.email)}\"\n    result = controller_instance.send(:is_valid?, token)\n    expect(Digest::SHA256).to have_received(:hexdigest).at_least(:once)\n  end\nend",
      "attackVector": "MD5 collision to bypass token validation",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "test_md5_collision_allows_unauthorized_reset",
      "testCode": "require 'rails_helper'\n\nRSpec.describe PasswordResetsController, type: :controller do\n  it 'fails when MD5 collision enables password reset for wrong user' do\n    user = User.create!(email: 'target@example.com', password: 'secure123')\n    colliding_email = 'attacker@example.com'\n    token = controller_instance.send(:generate_token, user.id, colliding_email)\n    expect(token).not_to match(/[a-f0-9]{32}/i)\n  end\nend",
      "attackVector": "Exploit MD5 weakness to generate colliding tokens",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}