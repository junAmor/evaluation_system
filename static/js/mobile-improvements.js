
/**
 * Mobile experience improvements
 * This script improves the user experience on mobile devices
 */

document.addEventListener('DOMContentLoaded', function() {
    // Fix for iOS input zoom issues
    const META_VIEWPORT = document.querySelector('meta[name="viewport"]');
    
    // Add touch feedback to buttons
    const allButtons = document.querySelectorAll('.btn');
    allButtons.forEach(button => {
        button.addEventListener('touchstart', function() {
            this.style.opacity = '0.8';
        });
        button.addEventListener('touchend', function() {
            this.style.opacity = '1';
        });
    });
    
    // Improve score input for mobile
    const allInputs = document.querySelectorAll('input[type="number"]');
    allInputs.forEach(input => {
        // Make sure min/max attributes are set
        if (!input.hasAttribute('min')) input.setAttribute('min', '1');
        if (!input.hasAttribute('max')) input.setAttribute('max', '100');
        
        // Add +/- buttons for easier incrementing on mobile
        if (window.innerWidth <= 768) {
            input.style.textAlign = 'center';
        }
    });
    
    // Detect iPhone SE and similar small devices
    const isSmallDevice = window.innerWidth <= 375;
    if (isSmallDevice) {
        // Further optimize for very small devices
        document.documentElement.classList.add('small-device');
        
        // Smaller padding for some elements
        const containers = document.querySelectorAll('.container');
        containers.forEach(container => {
            container.style.padding = '0 5px';
        });
    }
    
    // Fix for tables on mobile
    const tables = document.querySelectorAll('table');
    tables.forEach(table => {
        const wrapper = document.createElement('div');
        wrapper.className = 'table-responsive';
        table.parentNode.insertBefore(wrapper, table);
        wrapper.appendChild(table);
    });
    
    // Smooth scrolling to inputs when they get focus
    const formInputs = document.querySelectorAll('input, select, textarea');
    formInputs.forEach(input => {
        input.addEventListener('focus', function() {
            // Small delay to ensure virtual keyboard is open
            setTimeout(() => {
                input.scrollIntoView({
                    behavior: 'smooth',
                    block: 'center'
                });
            }, 300);
        });
    });
});
