import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import DashboardPage from "./pages/DashboardPage";
import DevicesPage from "./pages/DevicesPage";
import FindingsPage from "./pages/FindingsPage";
import RemediationPage from "./pages/RemediationPage";

export function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<DashboardPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="devices" element={<DevicesPage />} />
        <Route path="remediation" element={<RemediationPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

export default App;