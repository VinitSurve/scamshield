import React from 'react';
import ReactDOM from 'react-dom/client';
import { TestLabApp } from './TestLabApp';
import '../styles.css';

const rootElement = document.getElementById('root');
if (rootElement) {
  ReactDOM.createRoot(rootElement).render(
    <React.StrictMode>
      <TestLabApp />
    </React.StrictMode>
  );
}
