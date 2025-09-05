async function loadCVEs() {
    const perPage = document.getElementById("perPage").value;
    const response = await fetch(`/api/cves`);
    const data = await response.json();

    document.getElementById("totalRecords").innerText = "Total Records: " + data.length;
    const tbody = document.querySelector("#cveTable tbody");
    tbody.innerHTML = "";

    data.slice(0, perPage).forEach(cve => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td><a href="/cves/${cve.id}">${cve.id}</a></td>
            <td>${cve.published}</td>
            <td>${cve.lastModified}</td>
            <td>${cve.cvss_score || ''}</td>
        `;
        tbody.appendChild(row);
    });
}

window.onload = loadCVEs;
