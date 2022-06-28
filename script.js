//  Started at 10:54 6-27-2022

import React from 'react';
import { Route, Routes } from 'react-router-dom';
import ConfirmPassword from './components/auth/ConfirmPassword';
import EmailVerification from './components/auth/EmailVerification';
import ForgetPassword from './components/auth/ForgetPassword';
import Signin from './components/auth/Signin';
import Signup from './components/auth/Signup';
import Home from './components/home';
import NotFound from './components/NotFound';
import Navbar from "./components/user/Navbar";

export default function App() {
    return (
        <>
            <Navbar />
        <Routes>
            <Route path='/' element={<Home />}/>
            <Route path='/auth/signin' element={<Signin />}/>
            <Route path='/auth/signup' element={<Signup />}/>
            <Route path='/auth/verification' element={<EmailVerification />}/>
            <Route path='/auth/forget-password' element={<ForgetPassword />}/>
            <Route path='/auth/reset-password' element={<ConfirmPassword />}/>
            <Route path='*' element={<NotFound />}/>
        </Routes>
        </>
    )

}

import React, { useEffect, useState } from 'react'
import { ImSpinner3 } from 'react-icons/im'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { verifyPasswordResetToken } from '../../api/auth'
import { useNotification } from '../../hooks'
import { commonModalClasses } from '../../utils/theme'
import Container from '../Container'
import FormContainer from '../form/FormContainer'
import FormInput from '../form/FormInput'
import Submit from '../form/Submit'
import Title from '../form/Title'

export default function ConfirmPassword() {
    const [ isVerifying, setIsVerifying ] = useState(true);
    const [ isValid, setIsValid ] = useState(false);
    const [ searchParams ] = useSearchParams();
    const token = searchParams.get('token');
    const id = searchParams.get('id');

    const { updateNotification } = useNotification();
    const navigate = useNavigate();

    useEffect(() => {
        isValidToken()
    }, [])

    const isValidToken = async () => {
        const { error, valid } = await verifyPasswordResetToken(token, id);
        if(error) { 
            navigate('/auth/reset-password', { replace: true });
            return updateNotification('error', error);
        }

        if(!valid) {
            setIsValid(false);
            setIsVerifying(false);
            return navigate('/auth/reset-password', { replace: true });
        }

        setIsValid(true);
        setIsVerifying(true);
    };

    if (isVerifying)
    return (
      <FormContainer>
        <Container>
          <div className="flex space-x-2 items-center">
            <h1 className="text-4xl font-semibold dark:text-white text-primary">
              Please wait we are verifying your token!
            </h1>
            <ImSpinner3 className="animate-spin text-4xl dark:text-white text-primary" />
          </div>
        </Container>
      </FormContainer>
    );

    if (!isValid)
    return (
      <FormContainer>
        <Container>
          <h1 className="text-4xl font-semibold dark:text-white text-primary">
            Sorry the token is invalid!
          </h1>
        </Container>
      </FormContainer>
    );

    return (
        <FormContainer>
      <Container>
          <form className={commonModalClasses + ' w-96'}>
              <Title>Enter New Password</Title>
              <FormInput label='New Password' placeholder='********' name='password' type="password" />
              <FormInput label='Confirm Password' placeholder='********' name='confirmPassword' type="password" />
              <Submit value="Confirm Password" />
          </form>
      </Container>
      </FormContainer>
      );
}

import client from "./client"

export const createUser = async (userInfo) => {
    try {
        const { data } = await client.post('/user/create', userInfo);
        return data;
    } catch (error) {
        const {response} = error;
        if(response?.data) return response.data;

        return { error: error.message || error };
    }
}

export const verifyUserEmail = async (userInfo) => {
    try {
        const { data } = await client.post('/user/verify-email', userInfo);
        return data;
    } catch (error) {

        console.log(error.response?.data);
        const {response} = error;
        if(response?.data) return response.data;

        return { error: error.message || error };
    }
};

export const signInUser = async (userInfo) => {
    try {
        const { data } = await client.post('/user/sign-in', userInfo);
        return data;
    } catch (error) {

        console.log(error.response?.data);
        const {response} = error;
        if(response?.data) return response.data;

        return { error: error.message || error };
    }
};

export const getIsAuth = async (token) => {
    try {
        const { data } = await client.get('/user/is-auth', { 
            headers: {
                Authorization: 'Bearer ' + token,
                accept: 'application/json',
            },
         });
        return data;
    } catch (error) {

        console.log(error.response?.data);
        const {response} = error;
        if(response?.data) return response.data;

        return { error: error.message || error };
    }
};

export const forgetPassword = async (email) => {
    try {
        const { data } = await client.post('/user/forget-password', { email });
        return data;
    } catch (error) {

        console.log(error.response?.data);
        const {response} = error;
        if(response?.data) return response.data;

        return { error: error.message || error };
    }
};

export const verifyPasswordResetToken = async (token, userId) => {
    try {
        const { data } = await client.post('/user/verify-pass-reset-token', { token, userId });
        return data;
    } catch (error) {

        console.log(error.response?.data);
        const {response} = error;
        if(response?.data) return response.data;

        return { error: error.message || error };
    }
};

import React, { useState } from 'react'
import { forgetPassword } from '../../api/auth';
import { useNotification } from '../../hooks';
import { isValidEmail } from '../../utils/helper';
import { commonModalClasses } from '../../utils/theme';
import Container from "../Container"
import CustomLink from '../CustomLink';
import FormContainer from '../form/FormContainer';
import FormInput from '../form/FormInput';
import Submit from '../form/Submit';
import Title from '../form/Title';

export default function ForgetPassword() {
    const [email, setEmail] = useState('');

    const { updateNotification } = useNotification();

    const handleChange = ({target}) => {
        const { value, name } = target;
        setEmail(value);
    };

    const handleSubmit = async (e) => {
        e.preventDefault();  
        if(!isValidEmail(email)) return updateNotification('error', 'Ivalid email!');

        const { error, message } = await forgetPassword(email);
        if(error) return updateNotification('error', error);

        updateNotification('success', message);
      };

  return (
    <FormContainer>
  <Container>
      <form onSubmit={handleSubmit} className={commonModalClasses + ' w-96'}>
          <Title>Please Enter your Email</Title>
          <FormInput onChange={handleChange} value={email} label='Email' placeholder='john@gmail.com' name='email' />
          <Submit value="Send Link" />

          <div className="flex justify-between">
              <CustomLink to="/auth/signin">Sign in</CustomLink>
              <CustomLink to="/auth/signup">Sign up</CustomLink>
          </div>
      </form>
  </Container>
  </FormContainer>
  );
}

import React from 'react';
import {ImSpinner3} from 'react-icons/im';

export default function Submit({ value, busy }) {
  return <button type='submit' className='w-full rounded dark:bg-white bg-secondary dark:text-secondary text-white hover: bg-opacity-90 translate font-semibold left-lg cursor-pointer h-10 flex items-center justify-center' >
      {busy ? <ImSpinner3 className='animate-spin' /> : value}
    </button>
}

import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom';


import { createUser } from '../../api/auth';
import { useAuth, useNotification } from '../../hooks';
import { isValidEmail } from '../../utils/helper';
import { commonModalClasses } from '../../utils/theme';
import Container from "../Container"
import CustomLink from '../CustomLink';
import FormContainer from '../form/FormContainer';
import FormInput from '../form/FormInput';
import Submit from '../form/Submit';
import Title from '../form/Title';


const validateUserInfo = ({ name, email, password }) => {
    const isValidName = /^[a-z A-Z]+$/;

    if(!name.trim()) return { ok: false, error: 'Name is missing!' }
    if(!isValidName.test(name)) return { ok: false, error: 'Invalid name!' };

    if(!email.trim()) return { ok: false, error: 'Email is missing!' };
    if(!isValidEmail(email)) return { ok: false, error: 'Invalid email!' };

    if(!password.trim()) return { ok: false, error: 'Password is missing!' };
    if(password.length <8) return { ok: false, error: 'Password must be 8 characters long!' };

    return { ok: true }
}

export default function Signup() {

    const [userInfo, setUserInfo] = useState({
        name: '',
        email: '',
        password: '',
    });

    const navigate = useNavigate();
    const { authInfo } = useAuth();
    const { isLoggedIn } = authInfo;

    const { updateNotification } = useNotification()

    const handleChange = ({target}) => {
        const { value, name } = target;
        setUserInfo({...userInfo, [name]: value});
    };

    const handleSubmit = async (e) => {
      e.preventDefault();  
      const { ok, error } = validateUserInfo(userInfo);

      if(!ok) return updateNotification('error', error);

      const response = await createUser(userInfo);
      if(response.error) return console.log(response.error);

      navigate('/auth/verification', { 
          state: { user: response.user },
           replace: true ,
        });
    };

    useEffect(() => {
        // move user somewhere else
        if(isLoggedIn) navigate('/')
    }, [isLoggedIn]);

    const { name, email, password } = userInfo;

    return <FormContainer>
        <Container>
            <form onSubmit={handleSubmit} className={commonModalClasses + ' w-72'}>
                <Title>Sign up</Title>
                <FormInput value={name} onChange={handleChange} label='Name' placeholder='John Doe' name='name' />
                <FormInput value={email} onChange={handleChange} label='Email' placeholder='john@gmail.com' name='email' />
                <FormInput value={password} onChange={handleChange} label='Password' placeholder='********' name='password' type='password' />
                <Submit value='Sign up' />

                <div className="flex justify-between">
                    <CustomLink to="/auth/forget-password">Forgot password</CustomLink>
                    <CustomLink to="/auth/signin">Sign in</CustomLink>
                </div>
            </form>
        </Container>
        </FormContainer>
}

import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom';
import { useAuth, useNotification } from '../../hooks';
import { isValidEmail } from '../../utils/helper';
import { commonModalClasses } from '../../utils/theme';
import Container from "../Container"
import CustomLink from '../CustomLink';
import FormContainer from '../form/FormContainer';
import FormInput from '../form/FormInput';
import Submit from '../form/Submit';
import Title from '../form/Title';

const validateUserInfo = ({ email, password }) => {

    if(!email.trim()) return { ok: false, error: 'Email is missing!' };
    if(!isValidEmail(email)) return { ok: false, error: 'Invalid email!' };

    if(!password.trim()) return { ok: false, error: 'Password is missing!' };
    if(password.length <8) return { ok: false, error: 'Password must be 8 characters long!' };

    return { ok: true }
}

export default function Signin() {
    const [userInfo, setUserInfo] = useState({
        email: '',
        password: '',
    });

    const navigate = useNavigate();
    const { updateNotification } = useNotification();
    const {handleLogin, authInfo} = useAuth();
    const { isPending, isLoggedIn } = authInfo;

    const handleChange = ({target}) => {
        const { value, name } = target;
        setUserInfo({...userInfo, [name]: value});
    };

    const handleSubmit = async (e) => {
        e.preventDefault();  
        const { ok, error } = validateUserInfo(userInfo);
  
        if(!ok) return updateNotification('error', error);
        handleLogin(userInfo.email, userInfo.password);
      };

    useEffect(() => {
        // move user somewhere else
        if(isLoggedIn) navigate('/')
    }, [isLoggedIn]);

    return <FormContainer>
        <Container>
            <form onSubmit={handleSubmit} className={commonModalClasses + ' w-72'}>
                <Title>Sign in</Title>
                <FormInput value={userInfo.email} onChange={handleChange} label='Email' placeholder='john@gmail.com' name='email' />
                <FormInput value={userInfo.password} onChange={handleChange} label='Password' placeholder='********' name='password' type="password" />
                <Submit value='Sign in' busy={isPending} />

                <div className="flex justify-between">
                    <CustomLink to="/auth/forget-password">Forgot password</CustomLink>
                    <CustomLink to="/auth/signup">Sign up</CustomLink>
                </div>
            </form>
        </Container>
        </FormContainer>
}

export const isValidEmail = (email) => {
    const isValid = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;

    return isValid.test(email);
}

import React, { useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { verifyUserEmail } from '../../api/auth';
import { useAuth, useNotification } from '../../hooks';

import { commonModalClasses } from '../../utils/theme';
import Container from "../Container"
import FormContainer from '../form/FormContainer';
import Submit from '../form/Submit';
import Title from '../form/Title';

const OTP_LENGTH = 6;
let currentOTPIndex;

const isValidOTP = (otp) => {
    let valid = false;
  
    for (let val of otp) {
      valid = !isNaN(parseInt(val));
      if (!valid) break;
    }
  
    return valid;
  };

export default function EmailVerification() {
const [otp, setOtp] = useState(new Array(OTP_LENGTH).fill(''));
const [activeOtpIndex, setActiveOtpIndex] = useState(0);

const { isAuth, authInfo } = useAuth();
const { isLoggedIn } = authInfo;
const inputRef = useRef()
const {updateNotification} = useNotification();

const { state } = useLocation();
const user = state?.user;

const navigate = useNavigate();

const focusNextInputField = (index) => {
    setActiveOtpIndex(index + 1);
}
const focusPreviousInputField = (index) => {
    let nextIndex;
    const diff = index - 1;
    nextIndex = diff !== 0 ? diff : 0;

    setActiveOtpIndex(nextIndex);
}

const handleOtpChange = ({ target }) => {
    const { value } = target;
    const newOtp = [...otp];
    newOtp[currentOTPIndex] = value.substring(value.length - 1, value.length);
 
    if (!value) focusPreviousInputField(currentOTPIndex);
    else focusNextInputField(currentOTPIndex);
 
    setOtp([...newOtp]);
};

const handleKeyDown = ({ key }, index) => {
    currentOTPIndex = index;
    if (key === "Backspace") {
        focusPreviousInputField(currentOTPIndex);
     }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if(!isValidOTP(otp)) return updateNotification('error', 'Invalid OTP');

    // Submit OTP
    const {error, message, user: userResponse } = await verifyUserEmail({ 
        OTP: otp.join(''),
        userId: user.id,
    });
    if(error) return updateNotification('error', error);

    updateNotification('success', message);
   localStorage.setItem('auth-token', userResponse.token);
   isAuth();
  }

    useEffect(() => {
        inputRef.current?.focus();
    }, [activeOtpIndex])

    useEffect(() => {
        if(!user) navigate('/not-found');
        if(isLoggedIn) navigate('/');
    }, [user, isLoggedIn])

    // if(!user) return null;

  return <FormContainer>
  <Container>
      <form onSubmit={handleSubmit} className={commonModalClasses}>
          <div>
          <Title>Please enter the OTP to verify your account</Title>
          <p className='text-center dark:text-dark-subtle text-left-subtle'>OTP has been sent to your email</p>
          </div>

        <div className='flex justify-center items-center space-x-4'>
          {otp.map((_, index) => {
              return (
              <input
              ref={activeOtpIndex === index ? inputRef : null}
              key={index}
               type="number"
              value={otp[index] || ''}
              onChange={(e) => handleOtpChange(e, index)}
              onKeyDown={(e) => handleKeyDown(e, index)}
               className="w-12 h-12 border-2 dark:border-dark-subtle border-light-subtle dark:focus:border-white focus:border-primary rounded bg-transparent outline-none text-center dark:text-white text-primary font-semibold text-xl spin-button-none" />
              );
          })}
        </div>

          <Submit value="Verify Account" />    
      </form>
  </Container>
  </FormContainer>
}

import React from 'react'
import { BsFillSunFill } from 'react-icons/bs';
import { Link } from 'react-router-dom';
import { useAuth, useTheme } from '../../hooks';
import Container from '../Container';

export default function Navbar() {
    const {toggleTheme} = useTheme();
const { authInfo, handleLogout } = useAuth();
    const { isLoggedIn } = authInfo;

    return (
        <div className="bg-secondary shadow-sm shadow-gray-500">
            <Container className="p-2" >
            <div className="flex justify-between items-center">
                <Link to='/'>
                 <img src="./logo.png" alt="" className="h-10" /> 
                 </Link>

                    <ul className='flex items-center space-x-4'>
                        <li>
                            <button onClick={toggleTheme} className='dark:bg-white bg-dark-subtle p-1 rounded'>
                                <BsFillSunFill className='text-secondary size={24}' />
                            </button>
                        </li>
                        <li>
                            <input
                                type="text"
                                className="border-2 border-dark-subtle p-1 rounded bg-transparent text-xl outline-none focus:border-white transition text-white"
                                placeholder="search..."
                            />
                            </li>
                            <li></li>
                        <li>
                        {isLoggedIn? (
                        <button 
                        onClick={handleLogout} 
                        className='text-white font-semibold text-lg'>
                            Log out
                        </button>
                         ) : (
                        <Link 
                        className='text-white font-semibold text-lg'
                         to='auth/signin'
                         >
                        Login
                        </Link>
                        )}
                        </li>
                    </ul>
                </div>
            </Container>
        </div >
    );
}

import userEvent from '@testing-library/user-event';
import React, { createContext, useEffect, useState } from 'react'
import { getIsAuth, signInUser } from '../api/auth';

export const AuthContext = createContext();

const defaultAuthInfo = {
    profile: null,
    isLoggedIn: false,
    isPending: false,
    error: ''
}

export default function AuthProvider({children}) {
    const [authInfo, setAuthInfo] = useState({...defaultAuthInfo})

    const handleLogin = async (email, password) => {
        setAuthInfo({...authInfo, isPending: true});
        const {error, user} = await signInUser({email, password})
        if(error) {
            setAuthInfo({...authInfo, isPending: false, error});
        }

        setAuthInfo({ 
            profile: { ...user }, 
            isPending: false, 
            isLoggedIn: true, 
            error: '',
        });

        localStorage.setItem('auth-token', user.token);
    };

    const isAuth = async () => {
        const token = localStorage.getItem('auth-token')
        if(!token) return;

        setAuthInfo({...authInfo, isPending: true});
        const {error, user} = await getIsAuth(token);
        if(error) {
            setAuthInfo({...authInfo, isPending: false, error});
        }

        setAuthInfo({ 
            profile: { ...user }, 
            isPending: false, 
            isLoggedIn: true, 
            error: '',
        });
    };

    const handleLogout = () => {
        localStorage.removeItem('auth-token');
        setAuthInfo({ ...defaultAuthInfo });
    }

    useEffect(() => {
        isAuth()
    }, [])


    return (
    <AuthContext.Provider value={{authInfo, handleLogin, isAuth, handleLogout}}>
        {children}
    </AuthContext.Provider>
    );
}

import React from 'react'
import AuthProvider from './AuthProvider';
import NotificationProvider from './NotificationProvider';
import ThemeProvider from './ThemeProvider';

export default function ContextProviders({children}) {
  return (
    <AuthProvider>
        <NotificationProvider>
        <ThemeProvider> { children} </ThemeProvider>
        </NotificationProvider>
    </AuthProvider>
  );
}

import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import { BrowserRouter } from 'react-router-dom';

import './index.css';
import ContextProviders from './context';


const rootElement = document.getElementById("root");

const root = ReactDOM.createRoot(rootElement);
root.render(
    <BrowserRouter>
        <ContextProviders>
            <App />
        </ContextProviders>
    </BrowserRouter>
)

import { useContext } from "react"
import { AuthContext } from "../context/AuthProvider";
import { NotificationContext } from "../context/NotificationProvider";
import { ThemeContext } from "../context/ThemeProvider"

export const useTheme = () => useContext(ThemeContext);
export const useNotification = () => useContext(NotificationContext);
export const useAuth = () => useContext(AuthContext);

import React, { createContext, useState } from 'react'

export const NotificationContext = createContext();

let timeoutId;
export default function NotificationProvider( {children}) {
    const [notification, setNotification] = useState('');
    const [classes, setClasses] = useState('');

    const updateNotification = (type, value) => {
        if(timeoutId) clearTimeout(timeoutId);

        switch(type) {
            case 'error': 
                setClasses('bg-red-500');
                break;
            case 'success': 
                setClasses('bg-green-500');
                break;
                
            case 'warning': 
                setClasses('bg-orange-500');
                break;
            case 'default': 
                setClasses('bg-red-500');
        }
        setNotification(value);

        timeoutId = setTimeout(() => {
            setNotification('')
        }, 3000)
    };

    return (
        <NotificationContext.Provider value={{updateNotification}}>
            {children}
            {notification && (
            <div className="fixed left-1/2 -translate-x-1/2 top-24">
                <div className='bounce-custom shadow-md shadow-gray-400 rounded'>
                <p className={classes + ' text-white px-4 py-2 font-semibold'}>{notification}</p>
                </div>
            </div> )}
        </NotificationContext.Provider>
    )
}


.spin-button-none::-webkit-outter-spin-button,
.spin-button-none::-webkit-inner-spin-button {
    appearance: none;
}

.bounce-custom {
    animation: bounce-custom 0.5s;
}
@keyframes bounce-custom {
    from, to { transform: scale(1, 1); }
    25% { transform: scale(0.9, 1.1); }
    50% { transform: scale(1.1, 0.9); }
    75% { transform: scale(0.95, 1.05); }
}

@tailwind base;
@tailwind components;
@tailwind utilities;

import axios from 'axios'

const client = axios.create({ baseURL: 'http://localhost:8000/api' });

export default client;

import React from 'react'

export default function NotFound() {
    return <div>NotFound</div>;
}

import React, { children } from 'react'

export default function Title({ children }) {
  return (
    <h1 className='text-xl dark:text-white text-secondary font-semibold text-center'>{ children }</h1>
  )
}

export const commonModalClasses = "dark:bg-secondary bg-white drop-shadow-lg rounded p-6 space-y-6";

import React from 'react'

export default function FormInput({name, label, placeholder, ...rest}) {
  return (
    <div className='flex flex-col-reverse'>
        <input id={name} name={name} className='bg-transparent rounded border-2 dark:border-dark-subtle border-light-subtle w-full text-lg outline-none dark:focus:border-white focus:border-primary p-1 dark:text-white peer translate' placeholder={placeholder} 
        {...rest}
        />
        <label
         className='font-semibold dark:text-dark-subtle text-light-subtle dark:peer-focus:text-white peer-focus-text-primary translate self-start' htmlFor="email">
         {label}
        </label>
    </div>
  )
}

import React from 'react'
import { Link } from 'react-router-dom'

export default function CustomLink({to, children}) {
  return (
  <Link className='dark:text-dark-subtle text-light-subtle dark:hover:text-white hover:text-primary transition' to={to}>
      {children}
      </Link>
  )
}

import React, { createContext, useEffect } from 'react';

export const ThemeContext = createContext();

const defaultTheme = 'light';
const darkTheme = 'dark';

export default function ThemeProvider({children}) {
    const toggleTheme = () => {
        const oldTheme =  getTheme();
        const newTheme = oldTheme === defaultTheme ? darkTheme : defaultTheme;

        updateTheme(newTheme, oldTheme);
    };

    useEffect(() => {
        const theme = getTheme();
        if(!theme) updateTheme(defaultTheme);
        else updateTheme(theme);
    }, []);

  return ( 
  <ThemeContext.Provider value={{ toggleTheme }}>
      {children}
  </ThemeContext.Provider>
  );
}

const getTheme = () => localStorage.getItem('theme');

const updateTheme = (theme, themeToRemove) => {
    if(themeToRemove) document.documentElement.classList.remove(themeToRemove);

    document.documentElement.classList.add(theme);
    localStorage.setItem('theme', theme);
};

module.exports = {
    content: ["./src/**/*.{js,jsx}"],
    darkMode: "class",
    theme: {
        extend: {
            colors: {
                primary: "#171717",
                secondary: "#272727",
                "dark-subtle": "rgba(255, 255, 255, 0.5)",
                "light-subtle": "rgba(39, 39, 39, 0.5)",
            },
        },
    },
    plugins: [],
};

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="utf-8" />
  <link rel="icon" href="%PUBLIC_URL%/favicon.png" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="theme-color" content="#000000" />
  <meta name="description" content="Web site created using create-react-app" />
  <link rel="apple-touch-icon" href="%PUBLIC_URL%/logo.png" />
  <!--
      Notice the use of %PUBLIC_URL% in the tags above.
      It will be replaced with the URL of the `public` folder during the build.
      Only files inside the `public` folder can be referenced from the HTML.

      Unlike "/favicon.ico" or "favicon.ico", "%PUBLIC_URL%/favicon.ico" will
      work correctly both with client-side routing and a non-root public URL.
      Learn how to configure a non-root public URL by running `npm run build`.
    -->
    <base href="/">
  <title>5 star MRP</title>
</head>

<body>
  <noscript>You need to enable JavaScript to run this app.</noscript>
  <div id="root"></div>
  <!--
      This HTML file is a template.
      If you open it directly in the browser, you will see an empty page.

      You can add webfonts, meta tags, or analytics to this file.
      The build step will place the bundled scripts into the <body> tag.

      To begin the development, run `npm start` or `yarn start`.
      To create a production bundle, use `npm run build` or `yarn build`.
    -->
</body>

</html>

import React from "react";

export default function Home() {
    return <div>Home</div>;
}

import React from 'react'

export default function Container({ children, className }) {
    return <div className={"max-w-screen-xl mx-auto" + className}>{children}</div>
}


const jwt = require("jsonwebtoken");
const User = require("../models/user");
const EmailVerificationToken = require("../models/emailVerificationToken");
const PasswordResetToken = require("../models/passwordResetToken");
const { isValidObjectId } = require("mongoose");
const { generateOTP, generateMailTransporter } = require("../utils/mail");
const { sendError, generateRandomByte } = require("../utils/helper");
const { use } = require("bcrypt/promises");

exports.create = async (req, res) => {
  const { name, email, password } = req.body;

  const oldUser = await User.findOne({ email });

  if (oldUser) return sendError(res, "This email is already in use!");

  const newUser = new User({ name, email, password });
  await newUser.save();

  // generate 6 digit otp
  let OTP = generateOTP();

  // store otp inside our db
  const newEmailVerificationToken = new EmailVerificationToken({
    owner: newUser._id,
    token: OTP,
  });

  await newEmailVerificationToken.save();

  // send that otp to our user

  var transport = generateMailTransporter();

  transport.sendMail({
    from: "verification@reviewapp.com",
    to: newUser.email,
    subject: "Email Verification",
    html: `
      <p>Your verification OTP</p>
      <h1>${OTP}</h1>

    `,
  });

  res.status(201).json({
    message:
      "Please verify your email. OTP has been sent to your email accont!",
    user: { id: newUser._id, name: newUser.name, email: newUser.email, },
  });
};

exports.verifyEmail = async (req, res) => {
  const { userId, OTP } = req.body;

  if (!isValidObjectId(userId)) return res.json({ error: "Invalid user!" });

  const user = await User.findById(userId);
  if (!user) return sendError(res, "user not found!", 404);

  if (user.isVerified) return sendError(res, "user is already verified!");

  const token = await EmailVerificationToken.findOne({ owner: userId });
  if (!token) return sendError(res, "token not found!");

  const isMatched = await token.compareToken(OTP);
  if (!isMatched) return sendError(res, "Please submit a valid OTP!");

  user.isVerified = true;
  await user.save();

  await EmailVerificationToken.findByIdAndDelete(token._id);

  var transport = generateMailTransporter();

  transport.sendMail({
    from: "verification@reviewapp.com",
    to: user.email,
    subject: "Welcome Email",
    html: "<h1>Welcome to our app and thanks for choosing us.</h1>",
  });

  const jwtToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
  res.json({ 
    user: { id: user._id, name: user.name, email: user.email, token: jwtToken }
    , message: "Your email is verified." });
};

exports.resendEmailVerificationToken = async (req, res) => {
  const { userId } = req.body;

  const user = await User.findById(userId);
  if (!user) return sendError(res, "user not found!");

  if (user.isVerified)
    return sendError(res, "This email id is already verified!");

  const alreadyHasToken = await EmailVerificationToken.findOne({
    owner: userId,
  });
  if (alreadyHasToken)
    return sendError(
      res,
      "Only after one hour you can request for another token!"
    );

  // generate 6 digit otp
  let OTP = generateOTP();

  // store otp inside our db
  const newEmailVerificationToken = new EmailVerificationToken({
    owner: user._id,
    token: OTP,
  });

  await newEmailVerificationToken.save();

  // send that otp to our user

  var transport = generateMailTransporter();

  transport.sendMail({
    from: "verification@reviewapp.com",
    to: user.email,
    subject: "Email Verification",
    html: `
      <p>Your verification OTP</p>
      <h1>${OTP}</h1>

    `,
  });

  res.json({
    message: "New OTP has been sent to your registered email accout.",
  });
};

exports.forgetPassword = async (req, res) => {
  const { email } = req.body;

  if (!email) return sendError(res, "email is missing!");

  const user = await User.findOne({ email });
  if (!user) return sendError(res, "User not found!", 404);

  const alreadyHasToken = await PasswordResetToken.findOne({ owner: user._id });
  if (alreadyHasToken)
    return sendError(
      res,
      "Only after one hour you can request for another token!"
    );

  const token = await generateRandomByte();
  const newPasswordResetToken = await PasswordResetToken({
    owner: user._id,
    token,
  });
  await newPasswordResetToken.save();

  const resetPasswordUrl = `http://localhost:3000/auth/reset-password?token=${token}&id=${user._id}`;

  const transport = generateMailTransporter();

  transport.sendMail({
    from: "security@reviewapp.com",
    to: user.email,
    subject: "Reset Password Link",
    html: `
      <p>Click here to reset password</p>
      <a href='${resetPasswordUrl}'>Change Password</a>

    `,
  });

  res.json({ message: "Link sent to your email!" });
};

exports.sendResetPasswordTokenStatus = (req, res) => {
  res.json({ valid: true });
};

exports.resetPassword = async (req, res) => {
  const { newPassword, userId } = req.body;

  const user = await User.findById(userId);
  const matched = await user.comparePassword(newPassword);
  if (matched)
    return sendError(
      res,
      "The new password must be different from the old one!"
    );

  user.password = newPassword;
  await user.save();

  await PasswordResetToken.findByIdAndDelete(req.resetToken._id);

  const transport = generateMailTransporter();

  transport.sendMail({
    from: "security@reviewapp.com",
    to: user.email,
    subject: "Password Reset Successfully",
    html: `
      <h1>Password Reset Successfully</h1>
      <p>Now you can use new password.</p>

    `,
  });

  res.json({
    message: "Password reset successfully, now you can use new password.",
  });
};

exports.signIn = async (req, res, next) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return sendError(res, "Email/Password mismatch!");

  const matched = await user.comparePassword(password);
  if (!matched) return sendError(res, "Email/Password mismatch!");

  const { _id, name, role } = user;

  const jwtToken = jwt.sign({ userId: _id }, process.env.JWT_SECRET);

  res.json({ user: { id: _id, name, email, role, token: jwtToken } });
};

const { isValidObjectId } = require("mongoose");
const PasswordResetToken = require("../models/passwordResetToken");
const { sendError } = require("../utils/helper");
exports.isValidPassResetToken = async (req, res, next) => {
  const { token, userId } = req.body;

  if (!token.trim() || !isValidObjectId(userId))
    return sendError(res, "Invalid request!");

  const resetToken = await PasswordResetToken.findOne({ owner: userId });
  if (!resetToken)
    return sendError(res, "Unauthorized access, invalid request!");

  const matched = await resetToken.compareToken(token);
  if (!matched) return sendError(res, "Unauthorized access, invalid request!");

  req.resetToken = resetToken;
  next();
};

const jwt = require("jsonwebtoken");
const { sendError } = require("../utils/helper");
const User = require("../models/user");

exports.isAuth = async (req, res, next) => {
  const token = req.headers?.authorization;

  const jwtToken = token.split('Bearer ')[1]
  
  if(!jwtToken) return sendError(res, 'Invalid token!');
  const decode = jwt.verify(jwtToken, process.env.JWT_SECRET);
  const { userId } = decode;

  const user = await User.findById(userId);
  if(!user) return sendError(res, 'Invalid token user not found!', 404);

  req.user = user;
  next();
};

exports.isAdmin = async (req, res, next) => {
  const { user } = req;
  if (user.role === "admin") next();
  else return sendError(res, "unauthorized access!");
};

const express = require("express");
const jwt = require('jsonwebtoken');
const User = require("../models/user");
const {
  create,
  verifyEmail,
  resendEmailVerificationToken,
  forgetPassword,
  sendResetPasswordTokenStatus,
  resetPassword,
  signIn,
} = require("../controllers/user");
const { isValidPassResetToken } = require("../middlewares/user");
const {
  userValidtor,
  validate,
  validatePassword,
  signInValidator,
} = require("../middlewares/validator");
const { sendError } = require("../utils/helper");
const { isAuth } = require("../middlewares/auth");

const router = express.Router();

router.post("/create", userValidtor, validate, create);
router.post("/sign-in", signInValidator, validate, signIn);

router.post("/verify-email", verifyEmail);
router.post("/resend-email-verification-token", resendEmailVerificationToken);
router.post("/forget-password", forgetPassword);
router.post(
  "/verify-pass-reset-token",
  isValidPassResetToken,
  sendResetPasswordTokenStatus
);
router.post(
  "/reset-password",
  validatePassword,
  validate,
  isValidPassResetToken,
  resetPassword
);

router.get('/is-auth', isAuth, (req, res) => {
  const {user} = req;
  res.json({ user: { id: user._id, name: user.name, email: user.email } });
})

module.exports = router;

// Ended at 12:27 6-28-2022
