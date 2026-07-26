import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { ThemeProvider } from '@/theme/ThemeContext'
import { AigcProvider } from '@/context/AigcContext'
import { DemoServiceProvider } from '@/context/DemoServiceContext'
import App from './App'
import './index.css'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ThemeProvider>
      <AigcProvider>
        <DemoServiceProvider>
          <App />
        </DemoServiceProvider>
      </AigcProvider>
    </ThemeProvider>
  </StrictMode>,
)
