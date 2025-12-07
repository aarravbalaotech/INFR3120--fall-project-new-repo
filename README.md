Campus Marketplace & Student Hub- Cloud render link - https://nfr3120-fall25-project.onrender.com 
INFR3120 Fall 2025 - Project Part 1

Team Members: Aarrav, Raj, Harrison



1. Project Overview

Our Campus Marketplace & Student Hub is a web-based platform designed specifically for individual university campuses to facilitate student-to-student commerce, service exchange, and community engagement. Similar to Facebook Marketplace but campus-exclusive, this platform allows students to buy and sell products, offer and request services like tutoring or study groups, and discover campus-wide events through an integrated calendar system.

The platform addresses the unique needs of campus communities by creating a trusted marketplace environment where students can safely transact with their peers. By combining marketplace functionality with a student hub that houses event calendars and service listings, we create a centralized digital space that strengthens campus community connections and makes student life more convenient.

For Part 3  of this project, we will focus on implementing tgrid party authentication (Googel Oauth and Github Oauth )-We also implemented a profile page where users can customixe there profile picyire username and password -they can also connect their google and github account to their current account for ease of signn in -finally we improved the overall look of our site to match our theme -

2. Site Structure & Page Breakdown


Page Name
Key Features
Implementation Notes


Landing/Home Page


Hero section with site branding, custom team logo, navigation menu, featured marketplace items, upcoming events preview, call-to-action buttons
Welcoming design with clear navigation to all sections. "Create Listing" and "View Events" prominent CTAs




Marketplace Page


Grid/card view of all product listings, filter by category, search functionality, CRUD operations (Create, Read, Update, Delete listings), seller information, price display
Cards show: title, price, category, seller name, photo, condition. Users can add new listings and edit/delete their own




Services Page
Tutoring listings, study group postings, other campus services, CRUD operations, filter by subject/service type, contact information, availability
Grid/table view. Filter by subject. "Offer Service" and "Request Help" buttons. Service details include rates, subjects, availability
About/Team Page
eVENT cALENDAR pAGE
Calendar view of campus events, list view option, event details (date, time, location, description), CRUD operations for events, filter by event type/category
Timeline or calendar grid layout. "Add Event" button. Sort by date/category. Event cards with full details


About/Team PageTeam 


Team member profiles, project description, task delegation breakdown, GitHub links
Team bios with photos. Clear table showing who's responsible for what. Links to GitHub repo





Team bios with photos. Clear table showing who's responsible for what. Links to GitHub repo




3. CRUD Operations

Our platform implements full CRUD (Create, Read, Update, Delete) functionality across three main data types:

Marketplace Listings:
• Create: Users can post new product listings with title, description, price, category, condition, and photo
• Read: Browse all listings in grid/card format with search and filter capabilities
• Update: Listing owners can edit their posts to change details or mark as sold
• Delete: Users can remove their own listings from the marketplace

Campus Events:
• Create: Add new events with name, date, time, location, description, and event type
• Read: View all events in calendar or list format, filter by category
• Update: Event creators can modify event details as needed
• Delete: Remove events that are cancelled or completed

Services (Tutoring/Study Groups):
• Create: Post service offerings with subject, rate, availability, and contact info
• Read: Browse available services with filtering by subject area
• Update: Service providers can update their availability and rates
• Delete: Remove service listings when no longer available

Team Member
Primary Responsibilities
Aarrav
• Project Lead & Coordinator
• Landing/Home Page grid view and Nav bar setp  (HTML, CSS, JavaScript)
• Events  Page (CRUD implementation)
• Services Page (CRUD implementation)
• Demo video creation and editing
• GitHub repository setup and management
Marketplace Page (full CRUD implementation)
-Authentication -db connection -login splash screen -user creation and login backend 
-overall backend work 

Raj
• 
• Product listing cards/grid layout
• Database structure and backend logic for products
• Search and filter functionality
• Image upload handling for listings
-log in and register models 


Harrison
• Events Calendar Page (calendar UI components)
• About/Team Page (team profiles, bios, delegation table)
• Site-wide styling and CSS framework
• Responsive design implementation
• Deployment to cloud platform (Render/Netlify/Vercel) or Aarrav if there are difficulties 
• Peer evaluation coordination









Note: All team members must push code from their individual GitHub accounts to demonstrate contribution.

5. GitHub Repository & Submission Requirements

• Repository Name: "INFR3120-Fall25-Project" (public repository)
• Add all team members as collaborators
• Include this project document in the repository
• Ensure all members commit code from their personal accounts
• Deploy website to cloud platform (Render, Netlify, or Vercel)
• Include README.md with:
   - Project description
   - Team member names and contributions
   - Link to deployed site
   - Setup/installation instructions
• Record demo video (5-10 minutes) showing:
   - All pages and features
   - CRUD operations in action
   - Team member contributions explanation
• Submit peer evaluation individually

6. Technical Stack (Suggested)

Frontend:
• HTML5, CSS3, JavaScript
• Framework options: Bootstrap, Tailwind CSS, or custom CSS
• Consider: React.js or Vue.js (Maybe)

Backend:
• Node.js with Express.js
• Database: MongoDB, PostgreSQL, or Firebase
• RESTful API for CRUD operations

Deployment:
• Frontend: Netlify or Vercel
• Backend: Render or Railway
• Database: MongoDB Atlas 

7. Future Development (Post Part 1)

Phase 2 Features:
• Potential chat system 
   - Direct messaging between buyers/sellers
   - Group chat for study groups
   - In-app notifications

• User authentication & profiles
   - Student login with university email verification
   - Profile pages with ratings/reviews
   - Transaction history
   - Saved favorites/bookmarks

• Enhanced marketplace features
   - Image galleries for listings (multiple photos)
   - Wishlist/saved items
   - Price negotiation system
   - Category-specific filters
   - "Sold" status and archive

• Advanced event management
   - RSVP system (check box)
   - Event reminders/notifications
   - Recurring events
   - Event categories and tags

• Community features
   - Rating system for sellers and service providers
   - Report inappropriate listings
   - Moderator tools for campus admins
   - Community guidelines and safety tips

• Mobile responsiveness improvements
   - Progressive Web App (PWA) functionality
   - Mobile-first design optimizations
   - Push notifications for mobile devices
37000
---

End of Project Document
Last Updated: [Nov 13 Aarrav bala]
Team: Aarrav, Raj, Harrison
