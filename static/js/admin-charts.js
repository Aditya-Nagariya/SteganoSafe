document.addEventListener('DOMContentLoaded', function() {
  // Initialize encryption method distribution chart if it exists
  const encryptionChartElement = document.getElementById('encryptionChart');
  
  if (encryptionChartElement) {
    initEncryptionChart(encryptionChartElement);
  }
  
  // Initialize user activity chart if it exists
  const userActivityChartElement = document.getElementById('userActivityChart');
  
  if (userActivityChartElement) {
    initUserActivityChart(userActivityChartElement);
  }
  
  // Refresh stats button functionality
  const refreshStatsBtn = document.getElementById('refresh-stats');
  
  if (refreshStatsBtn) {
    refreshStatsBtn.addEventListener('click', function() {
      fetchEncryptionStats();
    });
  }
});

function initEncryptionChart(chartElement) {
  // Get data from data attributes
  const labelsStr = chartElement.getAttribute('data-labels');
  const dataStr = chartElement.getAttribute('data-values');
  
  // Parse JSON data
  let labels = [];
  let data = [];
  
  try {
    labels = JSON.parse(labelsStr || '[]');
    data = JSON.parse(dataStr || '[]');
  } catch (e) {
    console.error('Error parsing chart data:', e);
    return;
  }
  
  // Colors for the chart
  const colors = [
    'rgba(54, 162, 235, 0.8)',
    'rgba(255, 99, 132, 0.8)',
    'rgba(255, 206, 86, 0.8)',
    'rgba(75, 192, 192, 0.8)',
    'rgba(153, 102, 255, 0.8)'
  ];
  
  const borderColors = colors.map(color => color.replace('0.8', '1'));
  
  // Create chart
  new Chart(chartElement.getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: labels,
      datasets: [{
        data: data,
        backgroundColor: colors.slice(0, data.length),
        borderColor: borderColors.slice(0, data.length),
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: {
          position: 'bottom',
        },
        title: {
          display: true,
          text: 'Encryption Methods Distribution'
        },
        tooltip: {
          callbacks: {
            label: function(context) {
              const label = context.label || '';
              const value = context.formattedValue;
              const total = context.dataset.data.reduce((a, b) => a + b, 0);
              const percentage = Math.round((context.raw / total) * 100);
              return `${label}: ${value} (${percentage}%)`;
            }
          }
        }
      }
    }
  });
}

function initUserActivityChart(chartElement) {
  // Get data from data attributes
  const labelsStr = chartElement.getAttribute('data-labels');
  const dataStr = chartElement.getAttribute('data-values');
  
  // Parse JSON data
  let labels = [];
  let data = [];
  
  try {
    labels = JSON.parse(labelsStr || '[]');
    data = JSON.parse(dataStr || '[]');
  } catch (e) {
    console.error('Error parsing chart data:', e);
    return;
  }
  
  // Create chart
  new Chart(chartElement.getContext('2d'), {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Activity Count',
        data: data,
        backgroundColor: 'rgba(75, 192, 192, 0.6)',
        borderColor: 'rgba(75, 192, 192, 1)',
        borderWidth: 1
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      scales: {
        x: {
          beginAtZero: true
        }
      },
      plugins: {
        title: {
          display: true,
          text: 'Most Active Users'
        },
        legend: {
          display: false
        }
      }
    }
  });
}

function fetchEncryptionStats() {
  // Show loading state
  const statElements = document.querySelectorAll('[id^="count-"]');
  statElements.forEach(el => {
    el.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
  });
  
  fetch('/admin/api/stats')
    .then(response => response.json())
    .then(data => {
      // Update encryption method counts
      if (data.encryption_methods) {
        for (const [method, count] of Object.entries(data.encryption_methods)) {
          const countEl = document.getElementById(`count-${method}`);
          if (countEl) {
            countEl.textContent = count;
          }
        }
      }
      
      // Show success message
      const refreshBtn = document.getElementById('refresh-stats');
      if (refreshBtn) {
        const oldText = refreshBtn.textContent;
        refreshBtn.innerHTML = '<i class="bi bi-check2"></i> Updated';
        refreshBtn.classList.add('btn-success');
        refreshBtn.classList.remove('btn-outline-info');
        
        setTimeout(() => {
          refreshBtn.textContent = oldText;
          refreshBtn.classList.remove('btn-success');
          refreshBtn.classList.add('btn-outline-info');
        }, 2000);
      }
    })
    .catch(error => {
      console.error('Error fetching stats:', error);
      
      // Show error state
      const refreshBtn = document.getElementById('refresh-stats');
      if (refreshBtn) {
        refreshBtn.innerHTML = '<i class="bi bi-x"></i> Error';
        refreshBtn.classList.add('btn-danger');
        refreshBtn.classList.remove('btn-outline-info');
        
        setTimeout(() => {
          refreshBtn.textContent = 'Refresh Stats';
          refreshBtn.classList.remove('btn-danger');
          refreshBtn.classList.add('btn-outline-info');
        }, 2000);
      }
    });
}
