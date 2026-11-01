
const matrixCells = [
  {
    key: "tp",
    label: "True Positive",
    description: "Malicious predicted malicious",
    color: "bg-lime",
  },
  {
    key: "fn",
    label: "False Negative",
    description: "Malicious predicted benign",
    color: "bg-yellow",
  },
  {
    key: "fp",
    label: "False Positive",
    description: "Benign predicted malicious",
    color: "bg-coral",
  },
  {
    key: "tn",
    label: "True Negative",
    description: "Benign predicted benign",
    color: "bg-blue",
  },
];

export default function ConfusionMatrix({
  matrix,
  title = "Classification Confusion Matrix",
}) {
  if (!matrix) {
    return (
      <section className="nb-card p-5">
        <h2 className="text-lg font-black uppercase text-text">
          {title}
        </h2>
        <p className="mt-3 text-sm text-muted">
          Confusion matrix data is unavailable.
        </p>
      </section>
    );
  }

  const answered =
    matrix.tp + matrix.fp + matrix.fn + matrix.tn;

  return (
    <section className="nb-card min-w-0 p-4 sm:p-6">
      <h2 className="text-lg font-black uppercase text-text">
        {title}
      </h2>

      <p className="mt-2 text-xs text-muted">
        Rows represent actual labels. Columns represent
        predicted labels.
      </p>

      <div className="mt-6 overflow-x-auto">
        <table className="w-full min-w-70 border-collapse text-center text-xs sm:text-sm">
          <caption className="sr-only">
            Binary classification confusion matrix
          </caption>

          <thead>
            <tr>
              <th className="p-2" scope="col">
                Actual / Predicted
              </th>
              <th className="p-2" scope="col">Malicious</th>
              <th className="p-2" scope="col">Benign</th>
            </tr>
          </thead>

          <tbody>
            {[0, 1].map((row) => (
              <tr key={row}>
                <th scope="row" className="p-2 text-left">
                  {row === 0 ? "Malicious" : "Benign"}
                </th>

                {matrixCells
                  .slice(row * 2, row * 2 + 2)
                  .map((cell) => (
                    <td key={cell.key} className="p-1">
                      <div
                        className={`border-2 border-[#171717] p-3 text-[#171717] sm:p-5 ${cell.color}`}
                      >
                        <p className="text-2xl font-black tabular-nums sm:text-3xl">
                          {matrix[cell.key]}
                        </p>
                        <p className="mt-1 text-[10px] font-black uppercase">
                          {cell.label}
                        </p>
                      </div>
                    </td>
                  ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="mt-5 border-t-2 border-border pt-4 font-mono text-xs text-muted">
        Answered binary classifications: {answered}
      </p>

      <p className="mt-2 text-xs text-muted">
        Abstentions, API failures, and indeterminate
        ground-truth scenarios are not included in
        this binary matrix.
      </p>
    </section>
  );
}
