import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import App from './App';
import { sampleReport } from './sampleReport';

describe('OpenTrace app', () => {
  it('renders the landing page heading and CTA', () => {
    render(<App />);
    expect(screen.getByRole('heading', { name: /opentrace/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /scan target/i })).toBeInTheDocument();
  });

  it('renders synthetic demo report in demo mode', async () => {
    render(<App />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: /load sample report/i }));
    expect(screen.getByText(/synthetic example data/i)).toBeInTheDocument();
    expect(screen.getByText(/content-security-policy/i)).toBeInTheDocument();
  });

  it('detects invalid URLs', async () => {
    render(<App />);
    const user = userEvent.setup();
    await user.clear(screen.getByLabelText(/target url/i));
    await user.type(screen.getByLabelText(/target url/i), 'javascript:alert(1)');
    await user.click(screen.getByRole('button', { name: /scan target/i }));
    expect(screen.getByText(/only http and https urls are supported/i)).toBeInTheDocument();
  });
});
