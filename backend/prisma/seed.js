const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Starting database seed...');

  // Clear existing data
  await prisma.application.deleteMany();
  await prisma.savedJob.deleteMany();
  await prisma.job.deleteMany();
  await prisma.user.deleteMany();

  // Create Admin
  const adminPassword = await bcrypt.hash('admin123', 10);
  const admin = await prisma.user.create({
    data: {
      email: 'admin@jobportal.com',
      password: adminPassword,
      firstName: 'Admin',
      lastName: 'User',
      role: 'ADMIN',
      phone: '+1234567890',
      location: 'New York, USA',
      emailVerified: true,
      isActive: true
    }
  });

  // Create Employers
  const employerPassword = await bcrypt.hash('employer123', 10);
  const employers = await Promise.all([
    prisma.user.create({
      data: {
        email: 'techcorp@example.com',
        password: employerPassword,
        firstName: 'John',
        lastName: 'Smith',
        role: 'EMPLOYER',
        company: 'TechCorp Solutions',
        companyWebsite: 'https://techcorp.com',
        location: 'San Francisco, CA',
        phone: '+1234567891',
        bio: 'Leading technology company focused on innovative solutions',
        emailVerified: true
      }
    }),
    prisma.user.create({
      data: {
        email: 'startup@example.com',
        password: employerPassword,
        firstName: 'Sarah',
        lastName: 'Johnson',
        role: 'EMPLOYER',
        company: 'StartupHub',
        companyWebsite: 'https://startuphub.com',
        location: 'Austin, TX',
        phone: '+1234567892',
        bio: 'Fast-growing startup in the fintech space',
        emailVerified: true
      }
    }),
    prisma.user.create({
      data: {
        email: 'globaltech@example.com',
        password: employerPassword,
        firstName: 'Michael',
        lastName: 'Brown',
        role: 'EMPLOYER',
        company: 'Global Tech Inc',
        companyWebsite: 'https://globaltech.com',
        location: 'Seattle, WA',
        phone: '+1234567893',
        bio: 'Multinational technology corporation',
        emailVerified: true
      }
    })
  ]);

  // Create Candidates
  const candidatePassword = await bcrypt.hash('candidate123', 10);
  const candidates = await Promise.all([
    prisma.user.create({
      data: {
        email: 'john.developer@example.com',
        password: candidatePassword,
        firstName: 'John',
        lastName: 'Developer',
        role: 'CANDIDATE',
        location: 'Los Angeles, CA',
        phone: '+1234567894',
        skills: ['JavaScript', 'React', 'Node.js', 'PostgreSQL', 'Docker'],
        experience: 5,
        bio: 'Full-stack developer with 5 years of experience',
        resume: 'https://example.com/resumes/john-developer.pdf',
        emailVerified: true
      }
    }),
    prisma.user.create({
      data: {
        email: 'jane.designer@example.com',
        password: candidatePassword,
        firstName: 'Jane',
        lastName: 'Designer',
        role: 'CANDIDATE',
        location: 'New York, NY',
        phone: '+1234567895',
        skills: ['UI/UX', 'Figma', 'Adobe XD', 'HTML', 'CSS'],
        experience: 3,
        bio: 'Creative UI/UX designer passionate about user-centered design',
        resume: 'https://example.com/resumes/jane-designer.pdf',
        emailVerified: true
      }
    }),
    prisma.user.create({
      data: {
        email: 'mike.data@example.com',
        password: candidatePassword,
        firstName: 'Mike',
        lastName: 'Analyst',
        role: 'CANDIDATE',
        location: 'Chicago, IL',
        phone: '+1234567896',
        skills: ['Python', 'SQL', 'Tableau', 'Machine Learning', 'Statistics'],
        experience: 4,
        bio: 'Data analyst with expertise in machine learning',
        resume: 'https://example.com/resumes/mike-analyst.pdf',
        emailVerified: true
      }
    }),
    prisma.user.create({
      data: {
        email: 'emily.manager@example.com',
        password: candidatePassword,
        firstName: 'Emily',
        lastName: 'Manager',
        role: 'CANDIDATE',
        location: 'Boston, MA',
        phone: '+1234567897',
        skills: ['Project Management', 'Agile', 'Scrum', 'Leadership', 'Communication'],
        experience: 7,
        bio: 'Experienced project manager with PMP certification',
        resume: 'https://example.com/resumes/emily-manager.pdf',
        emailVerified: true
      }
    })
  ]);

  // Create Jobs
  const jobs = await Promise.all([
    // TechCorp Jobs
    prisma.job.create({
      data: {
        title: 'Senior Full Stack Developer',
        description: 'We are looking for an experienced Full Stack Developer to join our team. You will be responsible for developing and maintaining web applications using modern technologies.',
        company: 'TechCorp Solutions',
        location: 'San Francisco, CA',
        salary: '$120,000 - $160,000',
        salaryMin: 120000,
        salaryMax: 160000,
        jobType: 'FULL_TIME',
        requirements: ['5+ years experience', 'React/Node.js expertise', 'PostgreSQL', 'AWS knowledge', 'Strong problem-solving skills'],
        benefits: ['Health insurance', '401k matching', 'Remote work options', 'Professional development budget'],
        employerId: employers[0].id,
        applicationDeadline: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days from now
        viewCount: 150
      }
    }),
    prisma.job.create({
      data: {
        title: 'UI/UX Designer',
        description: 'Join our design team to create beautiful and intuitive user interfaces for our products.',
        company: 'TechCorp Solutions',
        location: 'San Francisco, CA',
        salary: '$90,000 - $120,000',
        salaryMin: 90000,
        salaryMax: 120000,
        jobType: 'FULL_TIME',
        requirements: ['3+ years UI/UX experience', 'Figma expertise', 'Portfolio required', 'Understanding of user research'],
        benefits: ['Health insurance', 'Creative freedom', 'Modern office', 'Team building events'],
        employerId: employers[0].id,
        applicationDeadline: new Date(Date.now() + 45 * 24 * 60 * 60 * 1000),
        viewCount: 89
      }
    }),

    // StartupHub Jobs
    prisma.job.create({
      data: {
        title: 'DevOps Engineer',
        description: 'We need a DevOps engineer to help us scale our infrastructure and improve our deployment processes.',
        company: 'StartupHub',
        location: 'Austin, TX',
        salary: '$110,000 - $140,000',
        salaryMin: 110000,
        salaryMax: 140000,
        jobType: 'FULL_TIME',
        requirements: ['Docker/Kubernetes', 'CI/CD pipelines', 'AWS/GCP', 'Infrastructure as Code', 'Python/Bash scripting'],
        benefits: ['Equity options', 'Flexible hours', 'Health insurance', 'Home office stipend'],
        employerId: employers[1].id,
        applicationDeadline: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000),
        viewCount: 234
      }
    }),
    prisma.job.create({
      data: {
        title: 'Marketing Intern',
        description: 'Great opportunity for a marketing student to gain hands-on experience in a fast-paced startup environment.',
        company: 'StartupHub',
        location: 'Austin, TX',
        salary: '$20/hour',
        salaryMin: 40000,
        salaryMax: 45000,
        jobType: 'INTERNSHIP',
        requirements: ['Marketing student', 'Social media skills', 'Creative thinking', 'Good communication'],
        benefits: ['Learning opportunities', 'Mentorship', 'Flexible schedule', 'Potential for full-time'],
        employerId: employers[1].id,
        applicationDeadline: new Date(Date.now() + 15 * 24 * 60 * 60 * 1000),
        viewCount: 67
      }
    }),

    // Global Tech Jobs
    prisma.job.create({
      data: {
        title: 'Data Scientist',
        description: 'Looking for a Data Scientist to analyze large datasets and build predictive models.',
        company: 'Global Tech Inc',
        location: 'Seattle, WA',
        salary: '$130,000 - $180,000',
        salaryMin: 130000,
        salaryMax: 180000,
        jobType: 'FULL_TIME',
        requirements: ['PhD or MS in relevant field', 'Python/R', 'Machine Learning', 'SQL', 'Statistical analysis'],
        benefits: ['Premium health insurance', 'Stock options', 'Research budget', 'Conference attendance'],
        employerId: employers[2].id,
        applicationDeadline: new Date(Date.now() + 40 * 24 * 60 * 60 * 1000),
        viewCount: 312
      }
    }),
    prisma.job.create({
      data: {
        title: 'Remote Frontend Developer',
        description: 'Join our distributed team as a Frontend Developer. Work from anywhere in the world!',
        company: 'Global Tech Inc',
        location: 'Remote',
        salary: '$100,000 - $130,000',
        salaryMin: 100000,
        salaryMax: 130000,
        jobType: 'REMOTE',
        requirements: ['React expertise', 'TypeScript', 'Testing libraries', 'Responsive design', 'Git'],
        benefits: ['Full remote', 'Flexible hours', 'Equipment budget', 'Annual retreat'],
        employerId: employers[2].id,
        applicationDeadline: new Date(Date.now() + 50 * 24 * 60 * 60 * 1000),
        viewCount: 456
      }
    }),
    prisma.job.create({
      data: {
        title: 'Contract Mobile Developer',
        description: '6-month contract for an experienced React Native developer to build our mobile app.',
        company: 'Global Tech Inc',
        location: 'Seattle, WA',
        salary: '$75/hour',
        salaryMin: 150000,
        salaryMax: 160000,
        jobType: 'CONTRACT',
        requirements: ['React Native', 'iOS/Android', 'API integration', 'App Store deployment'],
        benefits: ['High hourly rate', 'Remote option', 'Possibility of extension'],
        employerId: employers[2].id,
        applicationDeadline: new Date(Date.now() + 20 * 24 * 60 * 60 * 1000),
        viewCount: 178
      }
    })
  ]);

  // Create Applications
  await Promise.all([
    prisma.application.create({
      data: {
        candidateId: candidates[0].id,
        jobId: jobs[0].id,
        coverLetter: 'I am very interested in the Senior Full Stack Developer position. With my 5 years of experience...',
        status: 'INTERVIEW',
        notes: 'Strong candidate, schedule technical interview'
      }
    }),
    prisma.application.create({
      data: {
        candidateId: candidates[1].id,
        jobId: jobs[1].id,
        coverLetter: 'As a passionate UI/UX designer with 3 years of experience, I would love to join your team...',
        status: 'PENDING'
      }
    }),
    prisma.application.create({
      data: {
        candidateId: candidates[2].id,
        jobId: jobs[4].id,
        coverLetter: 'I am excited about the Data Scientist position at Global Tech Inc...',
        status: 'REVIEWED',
        notes: 'Good profile, needs more ML experience'
      }
    }),
    prisma.application.create({
      data: {
        candidateId: candidates[0].id,
        jobId: jobs[5].id,
        coverLetter: 'The Remote Frontend Developer role aligns perfectly with my skills...',
        status: 'PENDING'
      }
    }),
    prisma.application.create({
      data: {
        candidateId: candidates[3].id,
        jobId: jobs[2].id,
        coverLetter: 'Although I am a project manager, I have experience with DevOps practices...',
        status: 'REJECTED',
        notes: 'Not enough technical experience'
      }
    })
  ]);

  // Create Saved Jobs
  await Promise.all([
    prisma.savedJob.create({
      data: {
        userId: candidates[0].id,
        jobId: jobs[2].id
      }
    }),
    prisma.savedJob.create({
      data: {
        userId: candidates[0].id,
        jobId: jobs[3].id
      }
    }),
    prisma.savedJob.create({
      data: {
        userId: candidates[1].id,
        jobId: jobs[0].id
      }
    }),
    prisma.savedJob.create({
      data: {
        userId: candidates[2].id,
        jobId: jobs[4].id
      }
    })
  ]);

  console.log('✅ Database seeded successfully!');
  console.log('\n📧 Login Credentials:');
  console.log('─────────────────────');
  console.log('Admin: admin@jobportal.com / admin123');
  console.log('Employer: techcorp@example.com / employer123');
  console.log('Employer: startup@example.com / employer123');
  console.log('Candidate: john.developer@example.com / candidate123');
  console.log('Candidate: jane.designer@example.com / candidate123');
}

main()
  .catch((e) => {
    console.error('❌ Seed error:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
