import React from "react";
import {createRoot} from "react-dom/client";
import {SessionProvider} from "./auth/Session.jsx";
import App from "./App.jsx";
import "./styles.css";

createRoot(document.getElementById("root")).render(<React.StrictMode><SessionProvider><App /></SessionProvider></React.StrictMode>);
