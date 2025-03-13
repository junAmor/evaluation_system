
document.addEventListener('DOMContentLoaded', function() {
    const startButton = document.getElementById('startTest');
    const restartButton = document.getElementById('restartTest');
    const resultsDiv = document.getElementById('testResults');
    const progressBar = document.getElementById('testProgress');
    const statusDiv = document.getElementById('testStatus');
    const downloadSpeedElement = document.getElementById('downloadSpeed');
    const uploadSpeedElement = document.getElementById('uploadSpeed');
    const pingElement = document.getElementById('pingResult');
    const jitterElement = document.getElementById('jitterResult');

    // Test file URLs - we'll generate these dynamically
    const testUrls = [];
    for (let i = 1; i <= 10; i++) {
        testUrls.push(`/generate-test-file?size=${i * 1024 * 1024}&id=${Date.now()}`);
    }
    
    // Initialize
    let testInProgress = false;
    let pingResults = [];
    let downloadSpeeds = [];
    let uploadSpeeds = [];
    
    startButton.addEventListener('click', startSpeedTest);
    restartButton.addEventListener('click', () => {
        resetTest();
        startSpeedTest();
    });
    
    function resetTest() {
        pingResults = [];
        downloadSpeeds = [];
        uploadSpeeds = [];
        progressBar.style.width = '0%';
        downloadSpeedElement.textContent = '0.00';
        uploadSpeedElement.textContent = '0.00';
        pingElement.textContent = '0';
        jitterElement.textContent = '0';
        statusDiv.textContent = 'Starting test...';
    }
    
    function startSpeedTest() {
        if (testInProgress) return;
        
        testInProgress = true;
        startButton.classList.add('d-none');
        resultsDiv.classList.remove('d-none');
        resetTest();
        
        // Run the test sequence
        runPingTest()
            .then(() => runDownloadTest())
            .then(() => runUploadTest())
            .then(() => finalizeTest())
            .catch(error => {
                console.error('Test failed:', error);
                statusDiv.textContent = 'Test failed. Please try again.';
                testInProgress = false;
            });
    }
    
    function updateProgress(percent) {
        progressBar.style.width = `${percent}%`;
    }
    
    // Ping test
    async function runPingTest() {
        statusDiv.textContent = 'Testing ping...';
        updateProgress(10);
        
        // Run multiple ping tests
        for (let i = 0; i < 5; i++) {
            const startTime = performance.now();
            try {
                await fetch('/ping-test', { 
                    method: 'GET',
                    cache: 'no-store',
                    headers: {'Cache-Control': 'no-cache'}
                });
                const endTime = performance.now();
                const pingTime = endTime - startTime;
                pingResults.push(pingTime);
                
                // Update UI with current results
                const avgPing = Math.round(pingResults.reduce((a, b) => a + b, 0) / pingResults.length);
                pingElement.textContent = avgPing;
                
                // Calculate jitter (standard deviation of ping)
                if (pingResults.length > 1) {
                    const mean = pingResults.reduce((a, b) => a + b, 0) / pingResults.length;
                    const squaredDiffs = pingResults.map(x => Math.pow(x - mean, 2));
                    const variance = squaredDiffs.reduce((a, b) => a + b, 0) / pingResults.length;
                    const jitter = Math.round(Math.sqrt(variance));
                    jitterElement.textContent = jitter;
                }
                
                updateProgress(10 + (i * 2));
            } catch (error) {
                console.error('Ping test failed:', error);
            }
            
            // Wait a moment between pings
            await new Promise(resolve => setTimeout(resolve, 200));
        }
    }
    
    // Download speed test
    async function runDownloadTest() {
        statusDiv.textContent = 'Testing download speed...';
        updateProgress(20);
        
        for (let i = 0; i < testUrls.length; i++) {
            const url = testUrls[i];
            const startTime = performance.now();
            
            try {
                const response = await fetch(url + '&t=' + new Date().getTime(), {
                    cache: 'no-store',
                    headers: {'Cache-Control': 'no-cache'}
                });
                await response.blob(); // Wait for the entire file to download
                
                const endTime = performance.now();
                const duration = (endTime - startTime) / 1000; // in seconds
                const fileSize = (i + 1) * 1; // Size in MB
                const speed = fileSize / duration * 8; // Convert to Mbps
                
                downloadSpeeds.push(speed);
                
                // Show average download speed
                const avgSpeed = downloadSpeeds.reduce((a, b) => a + b, 0) / downloadSpeeds.length;
                downloadSpeedElement.textContent = avgSpeed.toFixed(2);
                
                // Update progress
                updateProgress(20 + ((i + 1) * 4));
                
                // Stop early if we detect good speed
                if (i > 3 && avgSpeed > 50) break;
                
            } catch (error) {
                console.error('Download test failed:', error);
            }
        }
    }
    
    // Upload speed test
    async function runUploadTest() {
        statusDiv.textContent = 'Testing upload speed...';
        updateProgress(60);
        
        // Create test data of different sizes
        const testSizes = [1, 2, 4, 8, 16].map(size => size * 1024 * 1024); // sizes in bytes
        
        for (let i = 0; i < testSizes.length; i++) {
            const size = testSizes[i];
            const testData = generateTestData(size);
            
            try {
                const startTime = performance.now();
                
                await fetch('/upload-test', {
                    method: 'POST',
                    body: testData,
                    headers: {
                        'Content-Type': 'application/octet-stream'
                    }
                });
                
                const endTime = performance.now();
                const duration = (endTime - startTime) / 1000; // in seconds
                const fileSize = size / (1024 * 1024); // Size in MB
                const speed = fileSize / duration * 8; // Convert to Mbps
                
                uploadSpeeds.push(speed);
                
                // Show average upload speed
                const avgSpeed = uploadSpeeds.reduce((a, b) => a + b, 0) / uploadSpeeds.length;
                uploadSpeedElement.textContent = avgSpeed.toFixed(2);
                
                // Update progress
                updateProgress(60 + ((i + 1) * 8));
                
                // Stop early if we detect good speed
                if (i > 1 && avgSpeed > 20) break;
                
            } catch (error) {
                console.error('Upload test failed:', error);
            }
        }
    }
    
    function generateTestData(size) {
        const buffer = new ArrayBuffer(size);
        const view = new Uint8Array(buffer);
        for (let i = 0; i < view.length; i++) {
            view[i] = Math.floor(Math.random() * 256);
        }
        return new Blob([buffer]);
    }
    
    function finalizeTest() {
        updateProgress(100);
        statusDiv.textContent = 'Test completed!';
        restartButton.classList.remove('d-none');
        testInProgress = false;
    }
});
