{
  "redTests": [
    {
      "testName": "mass_assignment_admin_privilege_escalation",
      "testCode": "require 'rails_helper'\n\nRSpec.describe AdminController, type: :controller do\n  it 'allows mass assignment of admin field via update_user' do\n    admin = User.create!(email: 'admin@test.com', password: 'password', admin: true)\n    user = User.create!(email: 'user@test.com', password: 'password', admin: false)\n    sign_in admin\n    \n    post :update_user, params: { admin_id: user.id, user: { admin: true } }, format: :json\n    \n    user.reload\n    expect(user.admin).to eq(true)\n  end\nend",
      "attackVector": "{ admin_id: user.id, user: { admin: true } }",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "mass_assignment_email_modification",
      "testCode": "require 'rails_helper'\n\nRSpec.describe AdminController, type: :controller do\n  it 'allows mass assignment of email field via update_user' do\n    admin = User.create!(email: 'admin@test.com', password: 'password', admin: true)\n    user = User.create!(email: 'user@test.com', password: 'password', admin: false)\n    sign_in admin\n    \n    post :update_user, params: { admin_id: user.id, user: { email: 'hacked@evil.com' } }, format: :json\n    \n    user.reload\n    expect(user.email).to eq('hacked@evil.com')\n  end\nend",
      "attackVector": "{ admin_id: user.id, user: { email: 'hacked@evil.com' } }",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "mass_assignment_multiple_protected_fields",
      "testCode": "require 'rails_helper'\n\nRSpec.describe AdminController, type: :controller do\n  it 'allows mass assignment of multiple protected fields' do\n    admin = User.create!(email: 'admin@test.com', password: 'password', admin: true)\n    user = User.create!(email: 'user@test.com', password: 'password', admin: false)\n    sign_in admin\n    \n    post :update_user, params: { admin_id: user.id, user: { admin: true, email: 'evil@test.com', role: 'superadmin' } }, format: :json\n    \n    user.reload\n    expect(user.admin).to eq(true)\n    expect(user.email).to eq('evil@test.com')\n  end\nend",
      "attackVector": "{ admin_id: user.id, user: { admin: true, email: 'evil@test.com', role: 'superadmin' } }",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}