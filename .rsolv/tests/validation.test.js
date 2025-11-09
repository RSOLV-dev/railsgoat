{
  "redTests": [
    {
      "testName": "cookie_missing_secure_flag",
      "testCode": "require 'rails_helper'\n\nRSpec.describe DashboardController, type: :controller do\n  it 'sets cookie without secure flag' do\n    get :home, params: { font: 'Arial' }\n    cookie = response.cookies['font']\n    expect(cookie).to be_present\n    expect(response.headers['Set-Cookie']).not_to include('secure')\n  end\nend",
      "attackVector": "font=Arial",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "cookie_missing_httponly_flag",
      "testCode": "require 'rails_helper'\n\nRSpec.describe DashboardController, type: :controller do\n  it 'sets cookie without httponly flag' do\n    get :home, params: { font: 'Verdana' }\n    cookie = response.cookies['font']\n    expect(cookie).to be_present\n    expect(response.headers['Set-Cookie']).not_to include('HttpOnly')\n  end\nend",
      "attackVector": "font=Verdana",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "cookie_missing_samesite_flag",
      "testCode": "require 'rails_helper'\n\nRSpec.describe DashboardController, type: :controller do\n  it 'sets cookie without samesite flag' do\n    get :home, params: { font: 'Times' }\n    cookie = response.cookies['font']\n    expect(cookie).to be_present\n    expect(response.headers['Set-Cookie']).not_to match(/SameSite=(Strict|Lax)/i)\n  end\nend",
      "attackVector": "font=Times",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    },
    {
      "testName": "cookie_vulnerable_to_xss_theft",
      "testCode": "require 'rails_helper'\n\nRSpec.describe DashboardController, type: :controller do\n  it 'cookie accessible via JavaScript due to missing httponly' do\n    get :home, params: { font: 'Comic Sans' }\n    expect(response.cookies['font']).to eq('Comic Sans')\n    expect(response.headers['Set-Cookie']).not_to include('HttpOnly')\n  end\nend",
      "attackVector": "font=Comic Sans",
      "expectedBehavior": "should_fail_on_vulnerable_code"
    }
  ]
}