import { QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { AuthProvider } from './auth/AuthProvider';
import { ToastProvider } from './components/ui/Toast';
import { AppRoutes } from './routes';
import { createQueryClient } from './lib/queryClient';

const queryClient = createQueryClient();

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      {/* The v7_startTransition / v7_relativeSplatPath flags are gone in react-router
          v7: they were v6 opt-ins for what is now the only behaviour. */}
      <BrowserRouter>
        <ToastProvider>
          <AuthProvider>
            <AppRoutes />
          </AuthProvider>
        </ToastProvider>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
