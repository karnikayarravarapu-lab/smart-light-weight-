import { useState } from "react";
import axios from "axios";

import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";

import "./index.css";

function App() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const handleFileChange = (event) => {
    setFile(event.target.files[0]);
    setResult(null);
  };

  const handleUpload = async () => {
    if (!file) {
      alert("Please select a CSV file.");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    try {
      setLoading(true);
      setResult(null);

      axios.post("YOUR_DEPLOYED_BACKEND_URL/predict-file", formData)

      console.log("SUCCESS:", response.data);

      setResult(response.data);

    } catch (error) {
      console.error("Axios Error:", error);

      console.log(
        "Status:",
        error.response?.status
      );

      console.log(
        "Backend Response:",
        error.response?.data
      );

      const backendError =
        error.response?.data?.error ||
        error.response?.data?.details ||
        error.message ||
        "Prediction failed.";

      alert(`Prediction failed:\n\n${backendError}`);

    } finally {
      setLoading(false);
    }
  };

  const chartData = result
    ? [
        {
          name: "Benign",
          value: result.benign_percentage,
        },
        {
          name: "Threat",
          value: result.threat_percentage,
        },
      ]
    : [];

  return (
    <div className="dashboard">

      <header>
        <h1>Cyber Threat Detection</h1>

        <p>
          AI-Based Network Security Analysis
        </p>
      </header>

      <section className="card upload-card">

        <h2>Upload Network Traffic CSV</h2>

        <p>
          Upload a CSV file to detect
          potential cyber threats.
        </p>

        <input
          type="file"
          accept=".csv"
          onChange={handleFileChange}
        />

        {file && (
          <p className="file-name">
            Selected: {file.name}
          </p>
        )}

        <button
          onClick={handleUpload}
          disabled={loading}
        >
          {loading
            ? "Analyzing..."
            : "Analyze File"}
        </button>

      </section>

      {result && (
        <>
          <section className="stats">

            <div className="stat-card">
              <h3>Total Records</h3>
              <strong>
                {result.total_records}
              </strong>
            </div>

            <div className="stat-card">
              <h3>Threats</h3>
              <strong>
                {result.threat_count}
              </strong>
            </div>

            <div className="stat-card">
              <h3>Benign</h3>
              <strong>
                {result.benign_count}
              </strong>
            </div>

          </section>

          <section className="card">

            <h2>Threat Detection Result</h2>

            <div className="percentage">

              <div>
                <span>Threat</span>

                <strong>
                  {result.threat_percentage}%
                </strong>
              </div>

              <div>
                <span>Benign</span>

                <strong>
                  {result.benign_percentage}%
                </strong>
              </div>

            </div>

          </section>

          <section className="card">

            <h2>Threat Analysis</h2>

            <ResponsiveContainer
              width="100%"
              height={350}
            >
              <PieChart>

                <Pie
                  data={chartData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={120}
                  label
                >
                  <Cell />
                  <Cell />
                </Pie>

                <Tooltip />

                <Legend />

              </PieChart>
            </ResponsiveContainer>

          </section>
        </>
      )}

    </div>
  );
}

export default App;
