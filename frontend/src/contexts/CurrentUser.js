import { createContext, useState, useEffect } from "react";

export const CurrentUser = createContext();

function CurrentUserProvider({ children }) {
  const [currentUser, setCurrentUser] = useState(null);

  const getLoggedInUser = async () => {
    let response = await fetch("http://localhost:5000/authentication/profile", {
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      }
    });
    let user = await response.json();
    setCurrentUser(user);
    console.log("sign in successful", user)
  };

  useEffect(() => {
    getLoggedInUser();
  }, []);

  return (
    <CurrentUser.Provider value={{ currentUser, setCurrentUser }}>
      {children}
    </CurrentUser.Provider>
  );
}

export default CurrentUserProvider;
