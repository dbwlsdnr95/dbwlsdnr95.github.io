document.addEventListener('DOMContentLoaded', () => {

    /* 1. Typing Effect */
    const typingText = document.querySelector('.typing-text');
    const words = ["Penetration Tester", "Security Researcher", "Ethical Hacker", "Problem Solver"];
    let wordIndex = 0;
    let charIndex = 0;
    let isDeleting = false;
    let typeSpeed = 100;

    function type() {
        if (!typingText) return;

        const currentWord = words[wordIndex];

        if (isDeleting) {
            typingText.textContent = currentWord.substring(0, charIndex - 1);
            charIndex--;
            typeSpeed = 50;
        } else {
            typingText.textContent = currentWord.substring(0, charIndex + 1);
            charIndex++;
            typeSpeed = 100;
        }

        if (!isDeleting && charIndex === currentWord.length) {
            isDeleting = true;
            typeSpeed = 2000;
        } else if (isDeleting && charIndex === 0) {
            isDeleting = false;
            wordIndex = (wordIndex + 1) % words.length;
            typeSpeed = 500;
        }

        setTimeout(type, typeSpeed);
    }

    // Start typing only if element exists (it's in Home view now)
    if (typingText) type();


    /* 2. View Switching Logic */
    const navLinks = document.querySelectorAll('.nav-links a');
    const views = document.querySelectorAll('.view-section');

    function showView(viewId) {
        // Remove active class from all views
        views.forEach(view => {
            view.classList.remove('active');
        });

        // Add active class to target view
        const targetView = document.getElementById(viewId);
        if (targetView) {
            targetView.classList.add('active');
        }

        // Update Nav Active State
        navLinks.forEach(link => {
            link.style.color = 'var(--text-secondary)'; // Reset
            link.style.textShadow = "none";
            if (link.getAttribute('href') === '#' + viewId) {
                link.style.color = 'var(--accent-blue)'; // Highlight active
            }
        });
    }

    // Handle Nav Clicks
    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = link.getAttribute('href').substring(1); // remove '#'
            showView(targetId);
        });
    });

    // Handle Button Click (e.g. "View Operations")
    window.navigateTo = (viewId) => {
        showView(viewId);
    };

    // Initial Load: Show Home
    showView('home');


    /* 3. Modal Logic for Projects */
    const modal = document.getElementById('project-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalDesc = document.getElementById('modal-desc');
    const modalRepoBtn = document.getElementById('modal-repo-btn');

    window.openModal = (projectId) => {
        const dataEl = document.getElementById(`data-${projectId}`);
        if (!dataEl) return;

        const title = dataEl.getAttribute('data-title');
        const desc = dataEl.getAttribute('data-desc');
        const repo = dataEl.getAttribute('data-repo');
        const detailId = dataEl.getAttribute('data-detail-id'); // Check for rich content

        modalTitle.textContent = title;

        if (detailId) {
            const detailSource = document.getElementById(detailId);
            if (detailSource) {
                modalDesc.innerHTML = detailSource.innerHTML;
                modalDesc.classList.add('rich-content'); // Add class for styling
            } else {
                modalDesc.innerHTML = desc;
                modalDesc.classList.remove('rich-content');
            }
        } else {
            modalDesc.innerHTML = desc;
            modalDesc.classList.remove('rich-content');
        }

        if (repo && repo !== '#' && repo !== null && !detailId) {
            modalRepoBtn.href = repo;
            modalRepoBtn.style.display = 'inline-block';
        } else {
            modalRepoBtn.style.display = 'none';
        }

        if (modal) {
            modal.classList.add('active');
        }
    };

    window.closeModal = () => {
        if (modal) {
            modal.classList.remove('active');
        }
    };

    // Close modal when clicking outside content
    window.onclick = (event) => {
        if (event.target === modal) {
            window.closeModal();
        }
    };

    /* 4. Arsenal Expand Toggle */
    const arsenalBtn = document.getElementById('toggle-arsenal');
    const arsenalContent = document.getElementById('arsenal-content');

    if (arsenalBtn && arsenalContent) {
        arsenalBtn.addEventListener('click', () => {
            arsenalContent.classList.toggle('show');
            arsenalBtn.classList.toggle('active');

            // Optional: Update text
            const textSpan = arsenalBtn.querySelector('span');
            if (arsenalContent.classList.contains('show')) {
                textSpan.textContent = "Hide Arsenal";
            } else {
                textSpan.textContent = "View Full Arsenal";
            }
        });
    }

});
