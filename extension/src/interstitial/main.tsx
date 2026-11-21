import React from 'react';
import ReactDOM from 'react-dom/client';
import { InterstitialApp } from './InterstitialApp';
import '../styles.css';

const rootElement = document.getElementById('root');
if (rootElement) {
  ReactDOM.createRoot(rootElement).render(
    <React.StrictMode>
      <InterstitialApp />
    </React.StrictMode>
  );
}
