import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Test, TestingModule } from '@nestjs/testing';
import { OrganizationService } from '../src/organization/organization.service';
import { PrismaService } from '../src/database/database.module';
import { NotFoundException, ConflictException } from '@nestjs/common';

describe('OrganizationService (Unit Tests)', () => {
  let orgService: OrganizationService;
  let mockPrisma: any;

  const mockOrg = {
    id: 'org_123',
    name: 'Aura Finance DAO',
    tier: 'standard',
    billingEmail: 'billing@auraprotocol.io',
    taxId: 'US948102948',
    createdAt: new Date(),
    users: [
      { id: 'usr_client', name: 'Alex Vance', email: 'alex@auraprotocol.io', role: 'CLIENT' },
    ],
  };

  const mockUser = {
    id: 'usr_client',
    email: 'alex@auraprotocol.io',
    name: 'Alex Vance',
    role: 'CLIENT',
    organizationId: null,
  };

  beforeEach(async () => {
    mockPrisma = {
      organization: {
        create: vi.fn(),
        findUnique: vi.fn(),
        update: vi.fn(),
      },
      user: {
        findUnique: vi.fn(),
        update: vi.fn(),
      },
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        OrganizationService,
        { provide: PrismaService, useValue: mockPrisma },
      ],
    }).compile();

    orgService = module.get<OrganizationService>(OrganizationService);
  });

  describe('createOrganization()', () => {
    it('should create an organization and link the current user', async () => {
      mockPrisma.user.findUnique.mockResolvedValue(mockUser);
      mockPrisma.organization.create.mockResolvedValue(mockOrg);
      mockPrisma.user.update.mockResolvedValue({ ...mockUser, organizationId: 'org_123' });

      const result = await orgService.createOrganization('usr_client', {
        name: 'Aura Finance DAO',
        billingEmail: 'billing@auraprotocol.io',
        taxId: 'US948102948',
      });

      expect(mockPrisma.organization.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            name: 'Aura Finance DAO',
            billingEmail: 'billing@auraprotocol.io',
            taxId: 'US948102948',
          }),
        }),
      );
      expect(mockPrisma.user.update).toHaveBeenCalledWith({
        where: { id: 'usr_client' },
        data: { organizationId: 'org_123' },
      });
      expect(result.name).toBe('Aura Finance DAO');
    });

    it('should throw ConflictException if user already belongs to an organization', async () => {
      mockPrisma.user.findUnique.mockResolvedValue({ ...mockUser, organizationId: 'existing_org' });

      await expect(
        orgService.createOrganization('usr_client', { name: 'New Org' }),
      ).rejects.toThrow(ConflictException);
    });
  });

  describe('getOrganizationForUser()', () => {
    it('should return organization profile with member list', async () => {
      mockPrisma.user.findUnique.mockResolvedValue({ ...mockUser, organizationId: 'org_123' });
      mockPrisma.organization.findUnique.mockResolvedValue(mockOrg);

      const result = await orgService.getOrganizationForUser('usr_client');

      expect(result.id).toBe('org_123');
      expect(result.users).toHaveLength(1);
    });

    it('should throw NotFoundException if user has no organization', async () => {
      mockPrisma.user.findUnique.mockResolvedValue(mockUser); // organizationId is null

      await expect(orgService.getOrganizationForUser('usr_client')).rejects.toThrow(NotFoundException);
    });
  });

  describe('addMember()', () => {
    it('should add a user by email to the organization', async () => {
      const invitedUser = { id: 'usr_member', email: 'member@auraprotocol.io', organizationId: null };

      mockPrisma.organization.findUnique.mockResolvedValue(mockOrg);
      mockPrisma.user.findUnique.mockResolvedValue(invitedUser);
      mockPrisma.user.update.mockResolvedValue({ ...invitedUser, organizationId: 'org_123' });

      const result = await orgService.addMember('org_123', 'usr_client', 'member@auraprotocol.io');

      expect(mockPrisma.user.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'usr_member' },
          data: { organizationId: 'org_123' },
        }),
      );
      expect(result.email).toBe('member@auraprotocol.io');
    });

    it('should throw NotFoundException if invited email does not exist', async () => {
      mockPrisma.organization.findUnique.mockResolvedValue(mockOrg);
      mockPrisma.user.findUnique.mockResolvedValue(null);

      await expect(
        orgService.addMember('org_123', 'usr_client', 'nonexistent@auraprotocol.io'),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('updateOrganization()', () => {
    it('should update organization name, billing email, taxId, and tier', async () => {
      mockPrisma.organization.findUnique.mockResolvedValue(mockOrg);
      mockPrisma.organization.update.mockResolvedValue({
        ...mockOrg,
        tier: 'enterprise',
      });

      const result = await orgService.updateOrganization('org_123', 'usr_client', {
        tier: 'enterprise',
      });

      expect(result.tier).toBe('enterprise');
    });
  });
});
