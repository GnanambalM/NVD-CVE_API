let cveData = [];
let currentPage = 1;

async function fetchCVEs(filters = {}) {
    let url = `/api/cves?`;
    if (filters.year) url += `year=${filters.year}&`;
    if (filters.score) url += `score=${filters.score}&`;
    if (filters.cveId) url += `id=${filters.cveId}&`;

    const response = await fetch(url);
    if (!response.ok) throw new Error("Cannot fetch CVEs");
    return await response.json();
}

async function loadCVEs(filters = {}) {
    try {
        cveData = await fetchCVEs(filters);
    } catch (err) {
        document.getElementById("totalRecords").innerText = "Failed to load CVEs";
        console.error(err);
        return;
    }
    currentPage = 1;
    renderTable();
}

function renderTable() {
    const perPage = parseInt(document.getElementById("perPage").value, 10) || 10;
    const tbody = document.querySelector("#cveTable tbody");
    tbody.innerHTML = "";

    const start = (currentPage - 1) * perPage;
    const end = Math.min(start + perPage, cveData.length);
    const pageData = cveData.slice(start, end);

    pageData.forEach(cve => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td><a href="/cves/${cve.id}" style="color:#222;text-decoration:underline;">${cve.id}</a></td>
            <td>${cve.identifier || 'cve@mitre.org'}</td>
            <td>${cve.published || ""}</td>
            <td>${cve.lastModified || ""}</td>
            <td>${cve.status || ""}</td>
            <td>${cve.cvss_score ?? ""}</td>
        `;
        tbody.appendChild(row);
    });

    document.getElementById("totalRecords").innerText = `Total Records: ${cveData.length}`;
    renderPagination(perPage, start, end);
}

function renderPagination(perPage, start, end) {
    const controls = document.getElementById("paginationControls");
    controls.innerHTML = "";
    const totalPages = Math.ceil(cveData.length / perPage) || 1;
	
	const maxPageDisplay = 5;
    let startPage = Math.max(currentPage - 2, 1);
    let endPage = Math.min(startPage + maxPageDisplay - 1, totalPages);
    if (endPage - startPage < maxPageDisplay - 1) {
        startPage = Math.max(endPage - maxPageDisplay + 1, 1);
    }

    const leftBtn = document.createElement("button");
    leftBtn.className = "arrow-btn";
    leftBtn.innerHTML = "&#9664;";
    leftBtn.disabled = currentPage === 1;
    leftBtn.onclick = () => { currentPage--; renderTable(); };
    controls.appendChild(leftBtn);

    for (let i = startPage; i <= endPage; i++) {
        const btn = document.createElement("button");
        btn.className = "page-btn" + (i === currentPage ? " active" : "");
        btn.innerText = i;
        btn.disabled = i === currentPage;
        btn.onclick = () => { currentPage = i; renderTable(); };
        controls.appendChild(btn);
    }

    const rightBtn = document.createElement("button");
    rightBtn.className = "arrow-btn";
    rightBtn.innerHTML = "&#9654;";
    rightBtn.disabled = currentPage === totalPages;
    rightBtn.onclick = () => { currentPage++; renderTable(); };
    controls.appendChild(rightBtn);

    document.getElementById("pageRange").innerText = `${start + 1}-${end} of ${cveData.length} records`;
}

function applyFilters() {
    const year = document.getElementById("year").value.trim();
    const score = document.getElementById("score").value.trim();
    const cveId = document.getElementById("cveId").value.trim();
    loadCVEs({ year, score, cveId });
}

document.getElementById("perPage").addEventListener("change", () => {
    currentPage = 1;
    renderTable();
});

window.onload = () => loadCVEs();
